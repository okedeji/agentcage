package runtime

import (
	"context"
	"fmt"
	"testing"

	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/reference"
)

func use(ref, version, digest string, deny ...string) bundle.UseSpec {
	return bundle.UseSpec{Ref: ref, Version: version, Digest: digest, Deny: deny}
}

func manifestUsing(uses ...bundle.UseSpec) *bundle.Manifest {
	return &bundle.Manifest{Agentfile: bundle.AgentfileSpec{Uses: uses}}
}

// fakePuller resolves a USES reference to a manifest keyed by digest, so a
// test can describe a tree without packing real bundles.
func fakePuller(byDigest map[string]*bundle.Manifest) pullManifest {
	return func(_ context.Context, ref reference.Reference) (string, *bundle.Manifest, error) {
		m, ok := byDigest[ref.Digest]
		if !ok {
			return "", nil, fmt.Errorf("no manifest for %s", ref.Digest)
		}
		return "/bundles/" + ref.Digest + ".agent", m, nil
	}
}

func TestResolveTree_TwoDeep(t *testing.T) {
	const (
		digA = "sha256:aaaaaaaaaaaa0000"
		digB = "sha256:bbbbbbbbbbbb0000"
	)
	root := manifestUsing(use("@org/a", "1.0", digA, "secret"))
	a := manifestUsing(use("@org/b", "2.0", digB))
	b := manifestUsing()

	tree, err := resolveTree(context.Background(), "root", "/root.agent", root,
		fakePuller(map[string]*bundle.Manifest{digA: a, digB: b}))
	if err != nil {
		t.Fatalf("resolveTree: %v", err)
	}

	if len(tree.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3 (root, a, b)", len(tree.Nodes))
	}
	if len(tree.Edges) != 2 {
		t.Fatalf("edges = %d, want 2", len(tree.Edges))
	}

	rootEdge := tree.Edges[0]
	if rootEdge.Caller != "root" || rootEdge.Alias != "a" {
		t.Errorf("root edge = %+v, want caller root alias a", rootEdge)
	}
	if len(rootEdge.Deny) != 1 || rootEdge.Deny[0] != "secret" {
		t.Errorf("root edge deny = %v, want [secret]", rootEdge.Deny)
	}
	// The sub-agent's own USES edge proves the walk recurses, so a deny
	// deep in the tree gets its own gateway edge.
	if tree.Edges[1].Caller != rootEdge.Sub || tree.Edges[1].Alias != "b" {
		t.Errorf("nested edge = %+v, want caller %s alias b", tree.Edges[1], rootEdge.Sub)
	}
}

func TestResolveTree_DedupesSharedSubAgent(t *testing.T) {
	const (
		digA = "sha256:aaaaaaaaaaaa0000"
		digB = "sha256:bbbbbbbbbbbb0000"
		digC = "sha256:cccccccccccc0000"
	)
	// root uses a and b; both use the same c (same digest), so c is one
	// container with two edges into it.
	root := manifestUsing(use("@org/a", "1.0", digA), use("@org/b", "1.0", digB))
	shared := manifestUsing(use("@org/c", "1.0", digC))
	c := manifestUsing()

	tree, err := resolveTree(context.Background(), "root", "/root.agent", root,
		fakePuller(map[string]*bundle.Manifest{digA: shared, digB: shared, digC: c}))
	if err != nil {
		t.Fatalf("resolveTree: %v", err)
	}

	if len(tree.Nodes) != 4 {
		t.Fatalf("nodes = %d, want 4 (root, a, b, c)", len(tree.Nodes))
	}
	intoC := 0
	for _, e := range tree.Edges {
		if e.Alias == "c" {
			intoC++
		}
	}
	if intoC != 2 {
		t.Errorf("edges into c = %d, want 2 (one per parent)", intoC)
	}
}

func TestResolveTree_MissingDigestIsError(t *testing.T) {
	root := manifestUsing(use("@org/a", "1.0", ""))
	_, err := resolveTree(context.Background(), "root", "/root.agent", root,
		fakePuller(nil))
	if err == nil {
		t.Fatal("resolveTree accepted a USES with no locked digest")
	}
}

func TestResolveTree_CycleTerminates(t *testing.T) {
	// A malformed pair where a points back at itself by digest. The walk
	// records the edge but never re-walks a seen node, so it terminates.
	const digA = "sha256:aaaaaaaaaaaa0000"
	a := manifestUsing(use("@org/a", "1.0", digA))
	root := manifestUsing(use("@org/a", "1.0", digA))

	tree, err := resolveTree(context.Background(), "root", "/root.agent", root,
		fakePuller(map[string]*bundle.Manifest{digA: a}))
	if err != nil {
		t.Fatalf("resolveTree: %v", err)
	}
	if len(tree.Nodes) != 2 {
		t.Errorf("nodes = %d, want 2 (root, a)", len(tree.Nodes))
	}
}

func TestUsesAlias(t *testing.T) {
	cases := map[string]string{
		"@org/web-search": "web-search",
		"@org/sub":        "sub",
		"plain":           "plain",
	}
	for in, want := range cases {
		if got := usesAlias(in); got != want {
			t.Errorf("usesAlias(%q) = %q, want %q", in, got, want)
		}
	}
}
