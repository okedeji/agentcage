package embedded

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	// Check if postgres is already available on the system
	path, err := exec.LookPath("postgres")
	if err == nil {
		p.binPath = filepath.Dir(path)
		p.log.Info("using system postgres", "path", path)
		return nil
	}

	// For embedded postgres, we rely on the system package manager or
	// a pre-built binary. In production this would use embedded-postgres-go
	// or download a static build.
	p.binPath = "/usr/lib/postgresql/" + postgresVersion + "/bin"
	if _, err := os.Stat(filepath.Join(p.binPath, "postgres")); err == nil {
		return nil
	}
	p.binPath = "/usr/bin"
	if _, err := os.Stat(filepath.Join(p.binPath, "postgres")); err == nil {
		return nil
	}

	return fmt.Errorf("postgres not found — install PostgreSQL %s or provide infrastructure.postgres.url in config", postgresVersion)
}

func (p *PostgresService) Start(ctx context.Context) error {
	pgData := filepath.Join(p.dataDir, "pgdata")

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
	conn.Close()
	return nil
}

func (p *PostgresService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+postgresPort, 500*time.Millisecond)
		if err == nil {
			conn.Close()
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
	defer db.Close()

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

func generatePassword() string {
	// For embedded dev mode, use a deterministic password.
	// Production deployments use external Postgres with proper auth.
	return "agentcage-embedded"
}
