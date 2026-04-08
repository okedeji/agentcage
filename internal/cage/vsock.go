package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// OTelSink forwards cage logs to an OpenTelemetry collector.
// Implementation requires the OTel logs SDK, wired in Phase 13.
type OTelSink struct{}

func (s *OTelSink) Write(cageID, source string, line []byte) error {
	return nil
}
