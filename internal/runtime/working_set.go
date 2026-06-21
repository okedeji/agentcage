package runtime

import (
	"context"
	"io"
	"sync"
)

// workingSet is a held run's live cages and the resources to manage them across
// its lifetime. M4 froze the cage set at boot; M5 makes it elastic, so the boot
// session, the resolved plan, and the teardown stack outlive boot here instead
// of dying with the closure bootTree used to return. The skeleton boots up
// front; the rest of the tree activates on demand (see activation.go) and is
// torn down with everything else on release.
//
// sess is the provisioner plus BuildKit client containers boot against. plan and
// tree are the resolved run, both nil for a single-container run with no USES.
// td is the same reverse-order, error-joining stack the boot helpers push onto.
type workingSet struct {
	mu sync.Mutex

	sess *bootSession
	plan *runPlan
	tree *runTree
	td   *teardown

	// specByNode maps a sub-agent node key to the planned container that runs it,
	// so an on-demand activation boots exactly the cage the plan already shaped.
	specByNode map[string]plannedAgent

	// live marks the nodes whose cage is up; inflight single-flights a node's
	// boot so concurrent first-calls wait on one activation rather than racing.
	live     map[string]bool
	inflight map[string]*activation

	// closing is set before teardown drains the stack. An activation that sees it
	// aborts, and a late push tears its own resource down rather than adding to a
	// stack already drained.
	closing bool

	// noCache and stderr are the build inputs an activation needs after boot:
	// whether to bypass the image cache, and where build progress goes.
	noCache bool
	stderr  io.Writer

	// cancel stops the activation supervisor. start sets it; releaseAll fires it
	// before draining so no cage is booted after teardown begins.
	cancel context.CancelFunc
}

// push adds a teardown step under the lock. Once the stack is closing it has
// already drained, so a step that arrives late (an activation that finished as
// the run came down) runs immediately rather than leaking onto a dead stack.
func (w *workingSet) push(step func() error) {
	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		_ = step()
		return
	}
	w.td.push(step)
	w.mu.Unlock()
}

// releaseAll stops the activation supervisor, then drains the teardown once,
// joining every step's error. cancel fires outside the lock because the
// supervisor's shutdown may need the lock the drain will take; closing is set
// under the lock first so no new activation slips past.
func (w *workingSet) releaseAll() error {
	w.mu.Lock()
	w.closing = true
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	return w.td.run()
}
