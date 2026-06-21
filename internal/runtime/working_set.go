package runtime

import "sync"

// workingSet is a held run's live cages and the resources to manage them across
// its lifetime. Today it boots its whole tree up front and only tears down; the
// reason it exists now is that M4 froze the cage set at boot, and M5 needs to
// add and reap cages while the run is held. So the boot session, the resolved
// plan, and the teardown stack outlive boot here instead of dying with the
// closure that bootTree used to return.
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
}

// releaseAll drains the teardown once under the lock, joining every step's
// error. The lock is what keeps a late activation from pushing onto a stack
// that is already being torn down.
func (w *workingSet) releaseAll() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.td.run()
}
