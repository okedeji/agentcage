// Package resolve turns the tags in a USES dependency graph into the
// digests the manifest lockfile records, and refuses graphs that loop
// back on themselves.
//
// Digest resolution is the cheap, always-run half: each direct
// dependency's tag is resolved against the registry to a digest. Cycle
// detection is the expensive half: it walks the transitive graph, pulling
// each sub-agent's manifest to read its own USES, and reports the first
// cycle it finds. A build can skip the walk for a large graph it trusts,
// at the cost of shifting that failure to first run.
package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/okedeji/agentcage/internal/agentfile"
	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/reference"
)

// registryClient is the slice of the registry the resolver needs. It is
// declared here, at the point of consumption, so tests can stand in a
// fake without a network or credentials. *registry.Client satisfies it.
type registryClient interface {
	Resolve(ctx context.Context, ref reference.Reference) (string, error)
	Pull(ctx context.Context, ref reference.Reference) (bundlePath, digest string, err error)
}

// Resolver resolves and validates a USES graph against a registry.
type Resolver struct {
	reg registryClient
}

// New returns a Resolver backed by reg.
func New(reg registryClient) *Resolver {
	return &Resolver{reg: reg}
}

// Options tune one Resolve call.
type Options struct {
	// ParentKey is the @org/name:version of the agent being built, taken
	// from `agentcage build -t`. When set, a transitive USES that points
	// back at it is reported as a cycle. Empty means the build was given
	// no tag, so a loop back to the parent cannot be named; dependency
	// internal cycles are still caught.
	ParentKey string

	// SkipCycleCheck skips the transitive walk. Digests are still
	// resolved. The escape hatch for graphs too large to walk on every
	// build, accepting that a cycle then surfaces at first run instead.
	SkipCycleCheck bool
}

// Result is what a successful Resolve returns.
type Result struct {
	// Digests maps each direct dependency's "@org/name:version" to the
	// digest its tag resolved to. The build looks each USES up here to
	// fill the manifest lockfile.
	Digests map[string]string
}

// Resolve locks every direct USES tag to a digest and, unless skipped,
// walks the transitive graph to reject cycles.
func (r *Resolver) Resolve(ctx context.Context, uses []agentfile.Use, opts Options) (Result, error) {
	digests := make(map[string]string, len(uses))
	for _, u := range uses {
		ref, err := refOf(u)
		if err != nil {
			return Result{}, err
		}
		digest, err := r.reg.Resolve(ctx, ref)
		if err != nil {
			return Result{}, fmt.Errorf("locking %s: %w", key(u), err)
		}
		digests[key(u)] = digest
	}

	if !opts.SkipCycleCheck {
		if err := r.checkCycles(ctx, opts.ParentKey, uses); err != nil {
			return Result{}, err
		}
	}
	return Result{Digests: digests}, nil
}

// checkCycles walks the dependency graph depth-first. A node already on
// the current path is a cycle; a node fully explored without one is cached
// so a diamond-shaped graph is not re-walked (and not re-pulled).
func (r *Resolver) checkCycles(ctx context.Context, parentKey string, uses []agentfile.Use) error {
	onPath := map[string]bool{}
	var path []string
	if parentKey != "" {
		onPath[parentKey] = true
		path = append(path, parentKey)
	}
	explored := map[string]bool{}
	cache := map[string][]agentfile.Use{}

	var visit func(uses []agentfile.Use) error
	visit = func(uses []agentfile.Use) error {
		for _, u := range uses {
			k := key(u)
			if onPath[k] {
				return fmt.Errorf("USES cycle: %s", strings.Join(append(append([]string{}, path...), k), " -> "))
			}
			if explored[k] {
				continue
			}
			children, err := r.subAgentUses(ctx, u, cache)
			if err != nil {
				return err
			}

			onPath[k] = true
			path = append(path, k)
			if err := visit(children); err != nil {
				return err
			}
			path = path[:len(path)-1]
			delete(onPath, k)
			explored[k] = true
		}
		return nil
	}
	return visit(uses)
}

// subAgentUses pulls a sub-agent's bundle and returns the USES it
// declares. Results are cached by key so each node is pulled at most once
// per resolution.
func (r *Resolver) subAgentUses(ctx context.Context, u agentfile.Use, cache map[string][]agentfile.Use) ([]agentfile.Use, error) {
	k := key(u)
	if cached, ok := cache[k]; ok {
		return cached, nil
	}
	ref, err := refOf(u)
	if err != nil {
		return nil, err
	}
	bundlePath, _, err := r.reg.Pull(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pulling %s for cycle check: %w", k, err)
	}
	manifest, err := bundle.ReadManifest(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s manifest: %w", k, err)
	}
	children := usesFromSpec(manifest.Agentfile.Uses)
	cache[k] = children
	return children, nil
}

// refOf reconstructs the OCI reference for a USES entry. The Agentfile
// parser splits the tag off into Version, so they are rejoined here.
func refOf(u agentfile.Use) (reference.Reference, error) {
	return reference.Parse(u.Ref + ":" + u.Version)
}

// key is a node's identity in the graph: its ref plus version, the same
// string the Agentfile author wrote.
func key(u agentfile.Use) string {
	return u.Ref + ":" + u.Version
}

// usesFromSpec narrows a manifest's USES entries to the ref and version
// the cycle walk needs. Digest, public, and deny do not affect graph
// shape.
func usesFromSpec(specs []bundle.UseSpec) []agentfile.Use {
	if len(specs) == 0 {
		return nil
	}
	out := make([]agentfile.Use, len(specs))
	for i, s := range specs {
		out[i] = agentfile.Use{Ref: s.Ref, Version: s.Version}
	}
	return out
}
