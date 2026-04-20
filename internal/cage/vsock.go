package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/go-logr/logr"
)

// LogSink is where collected log lines are sent. Implementations include
// OTel log exporters, stdout writers, or test buffers.
type LogSink interface {
	Write(cageID string, source string, line []byte) error
}

type VsockCollector struct {
	logger logr.Logger
	sink   LogSink
	mu     sync.Mutex
	conns  map[string]net.Conn
}

func NewVsockCollector(logger logr.Logger, sink LogSink) *VsockCollector {
	return &VsockCollector{
		logger: logger,
		sink:   sink,
		conns:  make(map[string]net.Conn),
	}
}

func (c *VsockCollector) CollectFromCage(ctx context.Context, cageID string, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)

	// 64KB max line size. Structured JSON logs from cage processes
	// can include request/response evidence; anything beyond 64KB is
	// almost certainly malformed.
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}

		line := scanner.Bytes()
		source := extractSource(line)

		if err := c.sink.Write(cageID, source, line); err != nil {
			c.logger.Error(err, "sink write failed", "cage_id", cageID, "source", source)
		}
	}

	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("scanning log stream for cage %s: %w", cageID, err)
	}

	return nil
}

func (c *VsockCollector) RegisterConn(cageID string, conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns[cageID] = conn
}

func (c *VsockCollector) StopCollecting(cageID string) {
	c.mu.Lock()
	conn, ok := c.conns[cageID]
	if ok {
		delete(c.conns, cageID)
	}
	c.mu.Unlock()

	if ok {
		_ = conn.Close() // best-effort; teardown races are expected
	}
}

func extractSource(line []byte) string {
	var envelope struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil || envelope.Source == "" {
		return "unknown"
	}
	return envelope.Source
}

type StdoutSink struct {
	logger logr.Logger
}

func NewStdoutSink(logger logr.Logger) *StdoutSink {
	return &StdoutSink{logger: logger}
}

func (s *StdoutSink) Write(cageID, source string, line []byte) error {
	s.logger.Info("cage log", "cage_id", cageID, "source", source, "raw", string(line))
	return nil
}

// FileSink writes cage logs to per-cage files under a directory.
// Each cage gets its own log file: <dir>/<cageID>.log. The CLI
// command `agentcage logs --cage <id>` tails this file.
type FileSink struct {
	dir    string
	mu     sync.Mutex
	files  map[string]*os.File
}

func NewFileSink(dir string) (*FileSink, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating cage log dir %s: %w", dir, err)
	}
	return &FileSink{dir: dir, files: make(map[string]*os.File)}, nil
}

func (s *FileSink) Write(cageID, source string, line []byte) error {
	s.mu.Lock()
	f, ok := s.files[cageID]
	if !ok {
		var err error
		path := fmt.Sprintf("%s/%s.log", s.dir, cageID)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("opening cage log %s: %w", path, err)
		}
		s.files[cageID] = f
	}
	s.mu.Unlock()

	entry := fmt.Sprintf("[%s] %s\n", source, line)
	_, err := f.WriteString(entry)
	return err
}

// Dir returns the log directory path for use by the CLI.
func (s *FileSink) Dir() string { return s.dir }

// Close closes all open log files.
func (s *FileSink) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.files {
		_ = f.Close()
	}
}

// OTelSink forwards cage logs to an OpenTelemetry collector.
// Implementation requires the OTel logs SDK, wired in Phase 13.
type OTelSink struct{}

func (s *OTelSink) Write(cageID, source string, line []byte) error {
	return nil
}
