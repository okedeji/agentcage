package runtime

import (
	"strings"
	"testing"

	"github.com/okedeji/mcpvessel/internal/vesselfile"
)

func TestGenerateDockerfile_Minimal(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 -m agent",
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})

	wantLines := []string{
		"FROM python:3.12-slim",
		"WORKDIR /agent",
		"COPY . /agent",
		`ENTRYPOINT ["sh", "-c", "python3 -m agent"]`,
	}
	for _, line := range wantLines {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

func TestGenerateDockerfile_ExecFormNoShell(t *testing.T) {
	// An exec-form ENTRYPOINT runs argv directly, so a distroless base with no
	// shell still boots. The sh -c wrapper must be absent.
	af := &vesselfile.Vesselfile{
		From:           "ghcr.io/github/github-mcp-server:0.16.0",
		Entrypoint:     "./mcpvessel mcp-bridge -- /server/github-mcp-server stdio",
		EntrypointExec: []string{"./mcpvessel", "mcp-bridge", "--", "/server/github-mcp-server", "stdio"},
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})

	want := `ENTRYPOINT ["./mcpvessel", "mcp-bridge", "--", "/server/github-mcp-server", "stdio"]`
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
	if strings.Contains(got, `"sh", "-c"`) {
		t.Errorf("exec form must not wrap in sh -c:\n%s", got)
	}
}

func TestGenerateDockerfile_RunStepsInOrder(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "node:20-slim",
		Entrypoint: "node dist/server.js",
		Run: []string{
			"npm ci",
			"npm run build",
		},
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})

	npmCI := strings.Index(got, "RUN npm ci")
	npmBuild := strings.Index(got, "RUN npm run build")
	if npmCI < 0 || npmBuild < 0 {
		t.Fatalf("RUN steps missing:\n%s", got)
	}
	if npmCI > npmBuild {
		t.Errorf("RUN steps emitted out of order")
	}
}

func TestGenerateDockerfile_RunPrecedesCopy(t *testing.T) {
	// RUN before COPY keeps the dependency install cached across source
	// edits; regressing this pushes rebuilds from seconds back to 20-30s.
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 agent.py",
		Run:        []string{"pip install mcp"},
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})

	runIdx := strings.Index(got, "RUN pip install mcp")
	copyIdx := strings.Index(got, "COPY . /agent")
	if runIdx < 0 || copyIdx < 0 {
		t.Fatalf("expected RUN and COPY lines, got:\n%s", got)
	}
	if runIdx > copyIdx {
		t.Errorf("RUN must precede COPY for cache friendliness; got RUN at %d, COPY at %d:\n%s",
			runIdx, copyIdx, got)
	}
}

func TestGenerateDockerfile_EnvDeterministic(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
		Env: map[string]string{
			"LOG_LEVEL": "info",
			"TZ":        "UTC",
			"TIMEOUT":   "30",
		},
	}
	// Output must be byte-identical regardless of map iteration order, or
	// BuildKit's cache key thrashes on every build.
	first := generateDockerfile(dockerfileInput{Vesselfile: af})
	for i := 0; i < 10; i++ {
		if got := generateDockerfile(dockerfileInput{Vesselfile: af}); got != first {
			t.Fatalf("non-deterministic codegen: ENV map iteration leaked into output")
		}
	}
}

func TestGenerateDockerfile_EnvValueWithSpaces(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
		Env: map[string]string{
			"GREETING": "hello world",
		},
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})
	if !strings.Contains(got, `ENV GREETING="hello world"`) {
		t.Errorf("ENV value with spaces not quoted:\n%s", got)
	}
}

func TestGenerateDockerfile_EnvValueSimple(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
		Env: map[string]string{
			"LEVEL": "info",
		},
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})
	if !strings.Contains(got, "ENV LEVEL=info\n") {
		t.Errorf("simple ENV value should not be quoted:\n%s", got)
	}
}

func TestGenerateDockerfile_LabelsSortedAndQuoted(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
	}
	got := generateDockerfile(dockerfileInput{
		Vesselfile: af,
		Labels: map[string]string{
			"io.mcpvessel.spec_version": "1",
			"io.mcpvessel.agent_ref":    "@okedeji/researcher:1.0",
			"io.mcpvessel.built_at":     "2026-06-07T00:00:00Z",
		},
	})

	idxAgentRef := strings.Index(got, "LABEL io.mcpvessel.agent_ref")
	idxBuiltAt := strings.Index(got, "LABEL io.mcpvessel.built_at")
	idxSpecVersion := strings.Index(got, "LABEL io.mcpvessel.spec_version")
	if idxAgentRef < 0 || idxBuiltAt < 0 || idxSpecVersion < 0 {
		t.Fatalf("expected labels missing:\n%s", got)
	}
	// Alphabetical: agent_ref < built_at < spec_version
	if idxAgentRef >= idxBuiltAt || idxBuiltAt >= idxSpecVersion {
		t.Errorf("labels not emitted in sorted order")
	}
	if !strings.Contains(got, `LABEL io.mcpvessel.agent_ref="@okedeji/researcher:1.0"`) {
		t.Errorf("label value not quoted:\n%s", got)
	}
}

func TestGenerateDockerfile_EmptyLabelsSkipped(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
	}
	got := generateDockerfile(dockerfileInput{
		Vesselfile: af,
		Labels: map[string]string{
			"io.mcpvessel.empty":   "",
			"io.mcpvessel.present": "yes",
		},
	})
	if strings.Contains(got, "io.mcpvessel.empty") {
		t.Errorf("empty-valued label should be skipped:\n%s", got)
	}
	if !strings.Contains(got, "io.mcpvessel.present") {
		t.Errorf("non-empty label should be present:\n%s", got)
	}
}

func TestGenerateDockerfile_EntrypointQuoting(t *testing.T) {
	// A multi-token entrypoint must land as one quoted sh -c argument.
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: `python3 -m agent --flag "value"`,
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})
	if !strings.Contains(got, `ENTRYPOINT ["sh", "-c", "python3 -m agent --flag \"value\""]`) {
		t.Errorf("entrypoint with embedded quotes not escaped:\n%s", got)
	}
}

func TestGenerateDockerfile_SyntaxDirectivePresent(t *testing.T) {
	af := &vesselfile.Vesselfile{
		From:       "python:3.12-slim",
		Entrypoint: "python3 main.py",
	}
	got := generateDockerfile(dockerfileInput{Vesselfile: af})
	// The "# syntax=" directive must appear early so BuildKit pulls the named
	// frontend before processing the rest of the file.
	if !strings.HasPrefix(got, "# Auto-generated") {
		t.Errorf("expected auto-generated header")
	}
	if !strings.Contains(got, "# syntax=docker/dockerfile:1") {
		t.Errorf("missing # syntax= parser directive:\n%s", got)
	}
}
