package cage

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSink struct {
	mu    sync.Mutex
	lines []sinkEntry
}

type sinkEntry struct {
	CageID string
	Source string
	Line   []byte
}

func (s *testSink) Write(cageID, source string, line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(line))
	copy(cp, line)
	s.lines = append(s.lines, sinkEntry{CageID: cageID, Source: source, Line: cp})
	return nil
}

func (s *testSink) getLines() []sinkEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sinkEntry, len(s.lines))
	copy(out, s.lines)
	return out
}

func TestCollectFromCage_SingleLine(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- collector.CollectFromCage(context.Background(), "cage-1", pr)
	}()

	_, err := fmt.Fprintln(pw, `{"source":"payload-proxy","msg":"started"}`)
	require.NoError(t, err)
	pw.Close()

	require.NoError(t, <-done)

	lines := sink.getLines()
	require.Len(t, lines, 1)
	assert.Equal(t, "cage-1", lines[0].CageID)
	assert.Equal(t, "payload-proxy", lines[0].Source)
	assert.JSONEq(t, `{"source":"payload-proxy","msg":"started"}`, string(lines[0].Line))
}

func TestCollectFromCage_MultipleLines(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- collector.CollectFromCage(context.Background(), "cage-2", pr)
	}()

	for i := range 5 {
		_, err := fmt.Fprintf(pw, `{"source":"agent","seq":%d}`+"\n", i)
		require.NoError(t, err)
	}
	pw.Close()

	require.NoError(t, <-done)

	lines := sink.getLines()
	require.Len(t, lines, 5)
	for i, entry := range lines {
		assert.Equal(t, "cage-2", entry.CageID)
		assert.Equal(t, "agent", entry.Source)
		expected := fmt.Sprintf(`{"source":"agent","seq":%d}`, i)
		assert.JSONEq(t, expected, string(entry.Line))
	}
}

func TestCollectFromCage_ContextCancellation(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- collector.CollectFromCage(ctx, "cage-3", pr)
	}()

	_, err := fmt.Fprintln(pw, `{"source":"agent","msg":"hello"}`)
	require.NoError(t, err)

	// Give the scanner time to process the line before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()
	pw.Close()

	require.NoError(t, <-done)
	assert.GreaterOrEqual(t, len(sink.getLines()), 1)
}

func TestCollectFromCage_ReaderClose(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- collector.CollectFromCage(context.Background(), "cage-4", pr)
	}()

	pw.Close()
	require.NoError(t, <-done)
}

func TestCollectFromCage_ConcurrentCages(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	cageIDs := []string{"cage-a", "cage-b", "cage-c"}
	var wg sync.WaitGroup

	for _, id := range cageIDs {
		pr, pw := io.Pipe()
		wg.Add(1)

		go func(cageID string, pw *io.PipeWriter) {
			defer pw.Close()
			for i := range 3 {
				fmt.Fprintf(pw, `{"source":"agent","cage":"%s","seq":%d}`+"\n", cageID, i)
			}
		}(id, pw)

		go func(cageID string, pr *io.PipeReader) {
			defer wg.Done()
			err := collector.CollectFromCage(context.Background(), cageID, pr)
			assert.NoError(t, err)
		}(id, pr)
	}

	wg.Wait()

	lines := sink.getLines()
	require.Len(t, lines, 9)

	counts := make(map[string]int)
	for _, entry := range lines {
		counts[entry.CageID]++
	}
	for _, id := range cageIDs {
		assert.Equal(t, 3, counts[id], "cage %s should have 3 lines", id)
	}
}

func TestCollectFromCage_UnknownSource(t *testing.T) {
	sink := &testSink{}
	collector := NewVsockCollector(logr.Discard(), sink)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- collector.CollectFromCage(context.Background(), "cage-5", pr)
	}()

	_, err := fmt.Fprintln(pw, `not json at all`)
	require.NoError(t, err)
	pw.Close()

	require.NoError(t, <-done)

	lines := sink.getLines()
	require.Len(t, lines, 1)
	assert.Equal(t, "unknown", lines[0].Source)
}
