package embedded

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	_ "github.com/lib/pq"
	"github.com/ulikunitz/xz"
)

const (
	postgresMajorVersion = "16"
	postgresVersion      = "16.6.0"
	postgresPort         = "15432"
	postgresUser         = "agentcage"
	postgresDB           = "agentcage"
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

	// Check common installation paths. Alpine 3.19+ puts postgresql
	// at /usr/libexec/postgresql<ver>/, Debian/Ubuntu at
	// /usr/lib/postgresql/<ver>/bin.
	for _, candidate := range []string{
		"/usr/libexec/postgresql" + postgresMajorVersion,
		"/usr/lib/postgresql/" + postgresMajorVersion + "/bin",
		"/usr/bin",
	} {
		fullPath := filepath.Join(candidate, "postgres")
		if _, err := os.Stat(fullPath); err == nil {
			p.binPath = candidate
			p.log.Info("using system postgres", "path", fullPath)
			return nil
		}
		p.log.Info("postgres not found", "checked", fullPath)
	}

	// Download embedded postgres binaries
	pgDir := filepath.Join(BinDir(), "postgres-"+postgresVersion)
	pgBin := filepath.Join(pgDir, "bin", "postgres")
	if _, err := os.Stat(pgBin); err == nil {
		p.binPath = filepath.Join(pgDir, "bin")
		return nil
	}

	arch := runtime.GOARCH
	if arch == "arm64" {
		arch = "arm64v8"
	}
	osName := runtime.GOOS

	url := fmt.Sprintf(
		"https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-%s-%s/%s/embedded-postgres-binaries-%s-%s-%s.jar",
		osName, arch, postgresVersion, osName, arch, postgresVersion,
	)

	p.log.Info("downloading postgres", "version", postgresVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "postgres-"+postgresVersion+".jar")
	if err := downloadBinaryWithLog(ctx, url, archivePath, p.log); err != nil {
		return fmt.Errorf("downloading postgres: %w. Install PostgreSQL %s or set infrastructure.postgres.url in config", err, postgresMajorVersion)
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
		if dataVersion != postgresMajorVersion {
			return fmt.Errorf("postgres data directory is version %s but binary is version %s. run pg_upgrade or remove %s to reinitialize", dataVersion, postgresMajorVersion, pgData)
		}
	}

	// Initialize data directory if it doesn't exist
	if _, err := os.Stat(filepath.Join(pgData, "PG_VERSION")); os.IsNotExist(err) {
		p.log.Info("initializing postgres data directory")
		initdb := filepath.Join(p.binPath, "initdb")
		if _, err := exec.LookPath("initdb"); err == nil {
			initdb = "initdb"
		}
		// Write a temporary password file for initdb --pwfile
		pwFile := filepath.Join(p.dataDir, "pwfile.tmp")
		if err := os.WriteFile(pwFile, []byte(p.password), 0600); err != nil {
			return fmt.Errorf("writing password file: %w", err)
		}

		cmd := exec.CommandContext(ctx, initdb,
			"-D", pgData,
			"-U", postgresUser,
			"--no-locale",
			"-E", "UTF8",
			"--auth=scram-sha-256",
			"--pwfile="+pwFile,
		)
		if os.Getuid() == 0 {
			_ = os.MkdirAll(pgData, 0700)
			_ = exec.Command("chown", "-R", "postgres:postgres", p.dataDir).Run()
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{Uid: 70, Gid: 70},
			}
		}
		out, err := cmd.CombinedOutput()
		_ = os.Remove(pwFile)
		if err != nil {
			return fmt.Errorf("initdb: %w\n%s", err, out)
		}

		// scram-sha-256 for all connections.
		hbaPath := filepath.Join(pgData, "pg_hba.conf")
		hba := "local all all scram-sha-256\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"
		if err := os.WriteFile(hbaPath, []byte(hba), 0600); err != nil {
			return fmt.Errorf("writing pg_hba.conf: %w", err)
		}
	}

	postgresBin := filepath.Join(p.binPath, "postgres")
	if _, err := exec.LookPath("postgres"); err == nil {
		postgresBin = "postgres"
	}

	socketDir := p.dataDir
	if os.Getuid() == 0 {
		socketDir = "/tmp"
	}
	p.proc = newSubprocess("postgres", p.log, postgresBin,
		"-D", pgData,
		"-p", postgresPort,
		"-k", socketDir,
		"-c", "shared_preload_libraries=timescaledb",
	)
	if os.Getuid() == 0 {
		p.proc.cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 70, Gid: 70},
		}
	}

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
	connStr := fmt.Sprintf("host=localhost port=%s user=%s password=%s dbname=postgres sslmode=disable",
		postgresPort, postgresUser, p.password)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		db, err := sql.Open("postgres", connStr)
		if err == nil {
			if err := db.PingContext(ctx); err == nil {
				_ = db.Close()
				return nil
			}
			_ = db.Close()
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
	connStr := fmt.Sprintf("host=localhost port=%s user=%s password=%s dbname=postgres sslmode=disable", postgresPort, postgresUser, p.password)
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
// containing a tar.gz or tar.xz of the postgres installation) into destDir.
func extractPostgresBinaries(jarPath, destDir string) error {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return fmt.Errorf("opening jar: %w", err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".tar.gz") {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening %s in jar: %w", f.Name, err)
			}
			err = extractTarGz(rc, destDir)
			_ = rc.Close()
			return err
		}
		if strings.HasSuffix(f.Name, ".txz") {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening %s in jar: %w", f.Name, err)
			}
			err = extractTarXz(rc, destDir)
			_ = rc.Close()
			return err
		}
	}
	return fmt.Errorf("no .tar.gz or .txz found in jar")
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

func extractTarXz(r io.Reader, destDir string) error {
	xr, err := xz.NewReader(r)
	if err != nil {
		return fmt.Errorf("opening xz: %w", err)
	}

	tr := tar.NewReader(xr)
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

// passwordPath returns the path where the generated Postgres password is stored.
func passwordPath() string {
	return filepath.Join(DataDir(), "secrets", "pg_password")
}

// PostgresURL returns the connection string for the embedded Postgres,
// reading the password from disk. Usable by any command that needs DB access.
func PostgresURL() (string, error) {
	pw, err := readPassword()
	if err != nil {
		return "", fmt.Errorf("reading embedded Postgres password: %w", err)
	}
	return fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable",
		postgresUser, pw, postgresPort, postgresDB), nil
}

func generatePassword() string {
	path := passwordPath()

	// Return existing password if already generated
	if data, err := os.ReadFile(path); err == nil {
		pw := strings.TrimSpace(string(data))
		if pw != "" {
			return pw
		}
	}

	// Generate a random 32-byte hex password
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: crypto/rand failed: %v\n", err)
		os.Exit(1)
	}
	pw := hex.EncodeToString(b)

	// Persist it
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0700)
	_ = os.WriteFile(path, []byte(pw), 0600)

	return pw
}

func readPassword() (string, error) {
	data, err := os.ReadFile(passwordPath())
	if err != nil {
		return "", err
	}
	pw := strings.TrimSpace(string(data))
	if pw == "" {
		return "", fmt.Errorf("password file is empty")
	}
	return pw, nil
}
