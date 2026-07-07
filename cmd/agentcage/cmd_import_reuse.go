package main

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/mcpregistry"
	"github.com/okedeji/agentcage/internal/store"
)

// wrapperCandidate is an existing wrapper of the server being imported: a tool
// collection carrying the same imported_from marker, either one already in the
// operator's store or one someone published to the registry.
type wrapperCandidate struct {
	Ref   string
	Eval  string
	Local bool
}

// chooseReuse offers any existing wrapper of the same server so an operator does
// not rebuild what already exists, their own or another's. It returns the ref to
// reuse, or "" to wrap a fresh one, which is also what an unmarked source (empty
// origin) or no candidates yields. Reuse is always advisory: interactively the
// operator picks, non-interactively the first candidate wins, and --no-reuse
// skips the whole thing. Nobody is made to depend on another's namespace.
func chooseReuse(cmd *cobra.Command, origin string) (string, error) {
	if origin == "" {
		return "", nil
	}
	cands, err := findLocalWrappers(origin)
	if err != nil {
		return "", err
	}
	cands = append(cands, findRegistryWrappers(cmd.Context(), origin)...)
	if len(cands) == 0 {
		return "", nil
	}

	w := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(w, "\n%s has already been wrapped:\n", origin)
	for i, c := range cands {
		_, _ = fmt.Fprintf(w, "  [%d] %s  (%s)\n", i+1, c.Ref, candidateProvenance(c))
	}

	if !isInteractive(cmd) {
		_, _ = fmt.Fprintf(w, "Reusing %s (pass --no-reuse to wrap your own).\n", cands[0].Ref)
		return cands[0].Ref, nil
	}

	_, _ = fmt.Fprint(w, "Reuse which, or 'w' to wrap your own? [1] ")
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	switch choice := strings.TrimSpace(line); choice {
	case "":
		return cands[0].Ref, nil
	case "w", "W":
		return "", nil
	default:
		if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(cands) {
			return cands[n-1].Ref, nil
		}
		return cands[0].Ref, nil
	}
}

// findLocalWrappers returns the operator's own prior wraps of this server, read
// off each stored bundle's imported_from marker. One entry per ref; a bundle no
// tag points at cannot be a USES target, so it is skipped.
func findLocalWrappers(origin string) ([]wrapperCandidate, error) {
	entries, err := store.List()
	if err != nil {
		return nil, err
	}
	s, err := store.New()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []wrapperCandidate
	for _, e := range entries {
		if e.Ref == "" || seen[e.Ref] {
			continue
		}
		m, err := bundle.ReadManifest(s.PathFor(e.Hash))
		if err != nil {
			continue
		}
		if m.Agentfile.Meta["imported_from"] != origin {
			continue
		}
		seen[e.Ref] = true
		out = append(out, wrapperCandidate{Ref: e.Ref, Local: true})
	}
	return out, nil
}

// findRegistryWrappers returns published wrappers of this server. Search matches
// on the entry name, so it casts by the server's short name and the marker
// narrows the hits to true wrappers of this very source. Best-effort: a registry
// outage returns nothing rather than failing an import that can proceed locally.
func findRegistryWrappers(ctx context.Context, origin string) []wrapperCandidate {
	servers, err := mcpregistry.New().Search(ctx, reuseSearchTerm(origin), 20)
	if err != nil {
		return nil
	}
	var out []wrapperCandidate
	for i := range servers {
		s := &servers[i]
		if s.ImportedFrom() != origin {
			continue
		}
		out = append(out, wrapperCandidate{Ref: s.Name, Eval: s.EvalSummary()})
	}
	return out
}

// reuseSearchTerm reduces an origin to the short name the registry search matches
// on: the last path or scheme segment, so npm:@scope/server-time and
// io.github.foo/server-time both cast for "server-time".
func reuseSearchTerm(origin string) string {
	if i := strings.LastIndexAny(origin, "/:"); i >= 0 {
		return origin[i+1:]
	}
	return origin
}

func candidateProvenance(c wrapperCandidate) string {
	where := "registry"
	if c.Local {
		where = "local"
	}
	if c.Eval != "" {
		return where + ", evals " + c.Eval
	}
	return where
}
