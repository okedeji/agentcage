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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var cageLogTracer = otel.Tracer("agentcage/cage-logs")

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
	ctx, span := cageLogTracer.Start(ctx, "cage.collectLogs",
		trace.WithAttributes(attribute.String("cage.id", cageID)),
	)
	defer span.End()

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
// command `agentcage logs cage <id>` tails this file.
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
	defer s.mu.Unlock()

	f, ok := s.files[cageID]
	if !ok {
		var err error
		path := fmt.Sprintf("%s/%s.log", s.dir, cageID)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening cage log %s: %w", path, err)
		}
		s.files[cageID] = f
	}

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

// MultiSink fans out writes to multiple sinks. If one fails, the
// rest still execute and the first error is returned.
type MultiSink struct {
	sinks []LogSink
}

func NewMultiSink(sinks ...LogSink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) Write(cageID, source string, line []byte) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Write(cageID, source, line); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NATSLogSink publishes cage log lines to NATS for live streaming.
// Subject pattern: cage.<cage-id>.logs
type NATSLogSink struct {
	pub NATSPublisher
}

// NATSPublisher is the subset of nats.Conn used by NATSLogSink.
type NATSPublisher interface {
	Publish(subject string, data []byte) error
}

func NewNATSLogSink(pub NATSPublisher) *NATSLogSink {
	return &NATSLogSink{pub: pub}
}

func (s *NATSLogSink) Write(cageID, source string, line []byte) error {
	subject := "cage." + cageID + ".logs"
	entry := fmt.Sprintf("[%s] %s", source, line)
	return s.pub.Publish(subject, []byte(entry))
}

func LogSubject(cageID string) string {
	return "cage." + cageID + ".logs"
}

// OTelLogSink exports cage log lines as short-lived OTel spans.
// Each write creates and immediately ends a span, so backends see
// individual log events without long-lived span lifetime issues.
type OTelLogSink struct{}

func NewOTelLogSink() *OTelLogSink {
	return &OTelLogSink{}
}

func (s *OTelLogSink) Write(cageID, source string, line []byte) error {
	_, span := cageLogTracer.Start(context.Background(), "cage.log",
		trace.WithAttributes(
			attribute.String("cage.id", cageID),
			attribute.String("source", source),
			attribute.String("message", string(line)),
		),
	)
	span.End()
	return nil
}
