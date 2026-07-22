package daemon

import (
	"net/http"

	"github.com/okedeji/mcpvessel/internal/runtime"
)

// handleRunSpend reports a live run's current LLM spend, read off the run's
// gateway; a finished run's cost lives in the history. A run that does not
// reason, or has stopped, is a 404.
func (d *Daemon) handleRunSpend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	report, ok := runtime.RunSpend(r.Context(), id)
	if !ok {
		writeError(w, http.StatusNotFound, "no live spend for run "+id+" (spend reads a live reasoning run; a finished run's total is in 'mcpvessel ps')")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
