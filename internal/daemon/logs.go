package daemon

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/okedeji/agentcage/internal/env"
)

// logsDirName is the per-run log directory under the agentcage home dir. Logs
// are files on disk, so `agentcage logs` reads a run that has ended and
// survives a daemon restart, while the history store holds only metadata.
const logsDirName = "logs"

// logTailInterval is how often a following reader rechecks a live run's log for
// new bytes. Short enough that a follow feels live, long enough that an idle
// agent does not spin the daemon.
const logTailInterval = 200 * time.Millisecond

// runLogPath is ~/.agentcage/logs/<run-id>.log.
func runLogPath(runID string) (string, error) {
	home, err := env.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, logsDirName, runID+".log"), nil
}

// openRunLog opens (creating) the append-only log file for a run, making the
// logs directory if it does not exist.
func openRunLog(runID string) (*os.File, error) {
	path, err := runLogPath(runID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// openRunLogSink opens a run's durable log for the runtime to tee the agent's
// stderr into. The runtime calls it once the run id is known, just before the
// agent container starts, so the agent's own output is captured and the earlier
// build progress is not. Best-effort: a log that will not open returns a no-op
// sink so the run still proceeds, logging to the stream alone.
func openRunLogSink(runID string) io.WriteCloser {
	f, err := openRunLog(runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: opening run log for %s: %v\n", runID, err)
		return nopWriteCloser{}
	}
	return f
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// handleRunLogs streams a run's log file. With follow=true it tails a live run,
// emitting new output until the run leaves the live set, then drains the final
// bytes and returns. A run with no log file (a serve front door, or one whose
// boot failed before it got a run id) is a 404.
func (d *Daemon) handleRunLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path, err := runLogPath(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "no logs for run "+id)
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	follow := r.URL.Query().Get("follow") == "true"
	buf := make([]byte, 32*1024)
	// finalPass drains once more after the run goes away, so output written
	// between the last read and the run leaving the live set is not lost.
	finalPass := false
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr == nil {
			continue
		}
		if rerr != io.EOF {
			return
		}
		if !follow || finalPass {
			return
		}
		if !d.isLive(id) {
			finalPass = true
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(logTailInterval):
		}
	}
}

// isLive reports whether a run is still in the live registry, the signal a
// following log reader uses to know when to stop tailing.
func (d *Daemon) isLive(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.runs[id]
	return ok
}
