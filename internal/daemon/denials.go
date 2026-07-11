package daemon

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// egressDenials tracks, per run, the hosts the egress proxy denied. It is fed
// by scanning the proxy events teed into the run's durable log, so a served
// tool error can explain that the cage blocked a host and the calling client
// (or an LLM) can relay it.
type egressDenials struct {
	mu    sync.Mutex
	byRun map[string]map[string]bool
}

func newEgressDenials() *egressDenials {
	return &egressDenials{byRun: map[string]map[string]bool{}}
}

func (e *egressDenials) record(runID, host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := e.byRun[runID]
	if set == nil {
		set = map[string]bool{}
		e.byRun[runID] = set
	}
	set[host] = true
}

// hosts returns the denied hosts for a run, sorted, or nil if none.
func (e *egressDenials) hosts(runID string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := e.byRun[runID]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (e *egressDenials) clear(runID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.byRun, runID)
}

// denialScanSink writes the run's log through to its file while scanning each
// line for the egress proxy's "egress denied: <host>" markers, recording every
// host so a tool error can name what the cage blocked.
type denialScanSink struct {
	w     io.WriteCloser
	runID string
	den   *egressDenials
	buf   bytes.Buffer
}

func (s *denialScanSink) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	s.buf.Write(p)
	for {
		data := s.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			break
		}
		line := string(data[:idx])
		s.buf.Next(idx + 1)
		if host, ok := parseDeniedHost(line); ok {
			s.den.record(s.runID, host)
		}
	}
	return n, err
}

func (s *denialScanSink) Close() error { return s.w.Close() }

// parseDeniedHost pulls the host from an "egress denied: <host> (agent ...)"
// line the proxy writes.
func parseDeniedHost(line string) (string, bool) {
	const marker = "egress denied: "
	i := strings.Index(line, marker)
	if i < 0 {
		return "", false
	}
	host, _, _ := strings.Cut(line[i+len(marker):], " ")
	host = strings.TrimSpace(host)
	return host, host != ""
}

// enrichEgressError appends the cage's blocked hosts to a tool error, so the
// caller learns the failure was the cage denying egress and how to allow it.
func enrichEgressError(err error, hosts []string) error {
	if err == nil || len(hosts) == 0 {
		return err
	}
	joined := strings.Join(hosts, ",")
	return fmt.Errorf("%w\nthe cage blocked this server from reaching %s; allow it with 'mcpvessel run/serve --egress %s', or bake it into the Vesselfile with EGRESS allow:%s and a rebuild",
		err, strings.Join(hosts, ", "), joined, joined)
}
