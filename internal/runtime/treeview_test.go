package runtime

import (
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/reference"
)

func TestNodeGlance_SummarizesOperationalAttributes(t *testing.T) {
	m := &bundle.Manifest{
		Agentfile: bundle.AgentfileSpec{
			Model:     "anthropic/claude-3.5",
			Budget:    5_000_000,
			Egress:    "deny-default",
			Resources: &bundle.ResourcesSpec{CPUs: "2", Mem: "2g"},
			Env:       map[string]string{"LOG_LEVEL": "info", "SYSTEM_PROMPT": ""},
			Secrets:   []string{"notion_token"},
		},
		Tools: []bundle.Tool{
			{Name: "respond", Visibility: bundle.VisibilityMain},
			{Name: "hidden", Visibility: bundle.VisibilityPrivate},
		},
	}
	g := nodeGlance(m)
	for _, want := range []string{
		"model=anthropic/claude-3.5", "budget=$5.00", "resources=cpu=2,mem=2g",
		"egress=deny-default", "env=[LOG_LEVEL,SYSTEM_PROMPT*]", "secrets=[notion_token]", "tools=1",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("glance %q missing %q", g, want)
		}
	}
	if nodeGlance(nil) != "" {
		t.Error("nil manifest should glance to empty")
	}
}

func TestRenderTreeChildren_NestedWithDeny(t *testing.T) {
	tree := &runTree{
		Root: "root",
		Nodes: map[string]*agentNode{
			"root":    {Key: "root"},
			"web-1":   {Key: "web-1", Ref: reference.Reference{Repository: "okedeji/web", Digest: "sha256:abc123def4567890"}},
			"fetch-2": {Key: "fetch-2", Ref: reference.Reference{Repository: "okedeji/fetch", Digest: "sha256:0000aaaa"}},
		},
		Edges: []usesEdge{
			{Caller: "root", Sub: "web-1", Alias: "web", Deny: []string{"deep_crawl"}},
			{Caller: "web-1", Sub: "fetch-2", Alias: "fetch"},
		},
	}

	var b strings.Builder
	renderTreeChildren(tree, "root", "", map[string]bool{"root": true}, &b)
	out := b.String()

	for _, want := range []string{
		"web  @okedeji/web  sha256:abc123def456", // digest truncated to 12
		"DENY deep_crawl",
		"fetch  @okedeji/fetch",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tree output missing %q:\n%s", want, out)
		}
	}
	// fetch is nested under web, so its line is indented past column 0.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "fetch") && !strings.HasPrefix(line, "   ") {
			t.Errorf("nested fetch not indented: %q", line)
		}
	}
}

func TestRenderTreeChildren_CycleTerminates(t *testing.T) {
	// A back-edge (a -> b -> a) must print (cycle) rather than recurse forever.
	tree := &runTree{
		Root: "root",
		Nodes: map[string]*agentNode{
			"root": {Key: "root"},
			"a-1":  {Key: "a-1", Ref: reference.Reference{Repository: "org/a"}},
			"b-2":  {Key: "b-2", Ref: reference.Reference{Repository: "org/b"}},
		},
		Edges: []usesEdge{
			{Caller: "root", Sub: "a-1", Alias: "a"},
			{Caller: "a-1", Sub: "b-2", Alias: "b"},
			{Caller: "b-2", Sub: "a-1", Alias: "a"},
		},
	}

	var b strings.Builder
	renderTreeChildren(tree, "root", "", map[string]bool{"root": true}, &b)
	if !strings.Contains(b.String(), "(cycle)") {
		t.Errorf("expected a (cycle) marker, got:\n%s", b.String())
	}
}
