package embedded

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"
	_ "github.com/lib/pq"
)

const (
	postgresVersion = "16"
	postgresPort    = "15432"
	postgresUser    = "agentcage"
	postgresDB      = "agentcage"
)

// PostgresService manages an embedded PostgreSQL instance.
type PostgresService struct {
	proc     *subprocess
	log      logr.Logger
	password string
	dataDir  string
	binPath  string
}

func NewPostgresService(log logr.Logger) *PostgresService {
	return &PostgresService{
		log:      log.WithValues("service", "postgres"),
		password: generatePassword(),
		dataDir:  ServiceDataDir("postgres"),
	}
}

func (p *PostgresService) Name() string      { return "postgres" }
func (p *PostgresService) IsExternal() bool   { return false }

func (p *PostgresService) URL() string {
	return fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable",
		postgresUser, p.password, postgresPort, postgresDB)
}

func (p *PostgresService) Download(ctx context.Context) error {
	// Prefer system postgres if available
	path, err := exec.LookPath("postgres")
	if err == nil {
		p.binPath = filepath.Dir(path)
		p.log.Info("using system postgres", "path", path)
		return nil
	}

	// Check common installation paths
	for _, candidate := range []string{
		"/usr/lib/postgresql/" + postgresVersion + "/bin",
		"/usr/bin",
	} {
		if _, err := os.Stat(filepath.Join(candidate, "postgres")); err == nil {
			p.binPath = candidate
			return nil
		}
	}

	// Download embedded postgres binaries
	pgDir := filepath.Join(BinDir(), "postgres-"+postgresVersion)
	pgBin := filepath.Join(pgDir, "bin", "postgres")
	if _, err := os.Stat(pgBin); err == nil {
		p.binPath = filepath.Join(pgDir, "bin")
		return nil
	}

	arch := runtime.GOARCH
	osName := runtime.GOOS

	url := fmt.Sprintf(
		"https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-%s-%s/%s.0/embedded-postgres-binaries-%s-%s-%s.0.jar",
		osName, arch, postgresVersion, osName, arch, postgresVersion,
	)

	p.log.Info("downloading postgres", "version", postgresVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "postgres-"+postgresVersion+".jar")
	if err := downloadBinary(ctx, url, archivePath); err != nil {
		return fmt.Errorf("downloading postgres: %w — install PostgreSQL %s or provide infrastructure.postgres.url in config", err, postgresVersion)
	}

	if err := extractPostgresBinaries(archivePath, pgDir); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting postgres: %w", err)
	}
	_ = os.Remove(archivePath)

	p.binPath = filepath.Join(pgDir, "bin")
	p.log.Info("postgres downloaded", "path", p.binPath)
	return nil
}

func (p *PostgresService) Start(ctx context.Context) error {
	pgData := filepath.Join(p.dataDir, "pgdata")

	// Verify data directory version matches the binary we're about to use
	versionFile := filepath.Join(pgData, "PG_VERSION")
	if raw, err := os.ReadFile(versionFile); err == nil {
		dataVersion := strings.TrimSpace(string(raw))
		if dataVersion != postgresVersion {
			return fmt.Errorf("postgres data directory is version %s but binary is version %s. run pg_upgrade or remove %s to reinitialize", dataVersion, postgresVersion, pgData)
		}
	}

	// Initialize data directory if it doesn't exist
	if _, err := os.Stat(filepath.Join(pgData, "PG_VERSION")); os.IsNotExist(err) {
		p.log.Info("initializing postgres data directory")
		initdb := filepath.Join(p.binPath, "initdb")
		if _, err := exec.LookPath("initdb"); err == nil {
			initdb = "initdb"
		}
		cmd := exec.CommandContext(ctx, initdb,
			"-D", pgData,
			"-U", postgresUser,
			"--no-locale",
			"-E", "UTF8",
		)
		cmd.Env = append(os.Environ(), "PGPASSWORD="+p.password)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("initdb: %w\n%s", err, out)
		}

		// Configure authentication
		hbaPath := filepath.Join(pgData, "pg_hba.conf")
		hba := "local all all trust\nhost all all 127.0.0.1/32 trust\nhost all all ::1/128 trust\n"
		if err := os.WriteFile(hbaPath, []byte(hba), 0600); err != nil {
			return fmt.Errorf("writing pg_hba.conf: %w", err)
		}
	}

	postgresBin := filepath.Join(p.binPath, "postgres")
	if _, err := exec.LookPath("postgres"); err == nil {
		postgresBin = "postgres"
	}

	p.proc = newSubprocess("postgres", p.log, postgresBin,
		"-D", pgData,
		"-p", postgresPort,
		"-k", p.dataDir,
	)

	if err := p.proc.start(ctx); err != nil {
		return err
	}

	// Wait for postgres to be ready
	if err := p.waitReady(ctx); err != nil {
		return fmt.Errorf("waiting for postgres: %w", err)
	}

	// Create database if it doesn't exist
	if err := p.ensureDatabase(ctx); err != nil {
		return fmt.Errorf("ensuring database: %w", err)
	}

	p.log.Info("postgres ready", "port", postgresPort, "url", p.URL())
	return nil
}

func (p *PostgresService) Stop(ctx context.Context) error {
	if p.proc == nil {
		return nil
	}
	return p.proc.stop(ctx)
}

func (p *PostgresService) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "localhost:"+postgresPort, 2*time.Second)
	if err != nil {
		return fmt.Errorf("postgres not reachable: %w", err)
	}
	_ = conn.Close()
	return nil
}

func (p *PostgresService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+postgresPort, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("postgres did not become ready within 30s")
}

func (p *PostgresService) ensureDatabase(ctx context.Context) error {
	connStr := fmt.Sprintf("host=localhost port=%s user=%s dbname=postgres sslmode=disable", postgresPort, postgresUser)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer func() { _ = db.Close() }()

	var exists bool
	err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", postgresDB).Scan(&exists)
	if err != nil {
		return fmt.Errorf("checking database existence: %w", err)
	}

	if !exists {
		_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", postgresDB))
		if err != nil {
			return fmt.Errorf("creating database: %w", err)
		}
		p.log.Info("created database", "name", postgresDB)
	}

	return nil
}

// extractPostgresBinaries unpacks the zonky embedded-postgres jar (a zip
// containing a tar.gz of the postgres installation) into destDir.
func extractPostgresBinaries(jarPath, destDir string) error {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return fmt.Errorf("opening jar: %w", err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".tar.gz") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s in jar: %w", f.Name, err)
		}
		err = extractTarGz(rc, destDir)
		_ = rc.Close()
		return err
	}
	return fmt.Errorf("no .tar.gz found in jar")
}

func extractTarGz(r io.Reader, destDir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("opening gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			return fmt.Errorf("path traversal in tar: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("creating directory %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("creating parent for %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("creating file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("writing %s: %w", target, err)
			}
			_ = f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("creating symlink %s: %w", target, err)
			}
		}
	}
	return nil
}

func generatePassword() string {
	// For local mode, use a deterministic password.
	// Production uses external Postgres with proper auth.
	return "agentcage-embedded"
}
