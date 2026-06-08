package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/agentfile"
	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/mcp"
)

// RunInput drives Run. Mostly mirrors the CLI's `agentcage run` and
// `agentcage call` flags.
type RunInput struct {
	// BundlePath is the .agent file the operator wants to run.
	BundlePath string

	// Tool is the MCP tool name to call. The CLI is responsible for
	// resolving it: `agentcage run` passes the bundle's main tool,
	// `agentcage call` passes the explicit name the operator gave.
	// Required.
	Tool string

	// Args is the MCP tools/call argument map. Marshaled to JSON by
	// the SDK and validated against the agent's input schema.
	Args map[string]any

	// RunID names the containerd container; if empty Run derives one
	// from the bundle's hash plus a unique suffix.
	RunID string

	// Stdout / Stderr receive provisioning progress, the agent's
	// stderr stream, and the final tool result. Callers typically
	// pass os.Stdout and os.Stderr; tests can capture into a buffer.
	Stdout io.Writer
	Stderr io.Writer

	// Verbose, when true, streams the underlying provisioner output
	// (Lima's stdout/stderr on macOS) directly to Stderr instead of
	// the clean phase UI. Operators set this with `--verbose` when
	// the polite renderer is hiding something they need to see.
	Verbose bool
}

// Run is the end-to-end flow behind `agentcage run`. It:
//
//  1. Extracts the bundle into a temp directory.
//  2. Asks the platform provisioner to make sure containerd and
//     buildkitd are reachable (provisioning the macOS Lima VM the
//     first time it sees one).
//  3. Builds the agent's image into containerd's local image store.
//  4. Creates a container + task with the agent's stdio piped.
//  5. Speaks MCP to the agent: lists its tools, picks one based on
//     input.Tool and pickTool's rules, calls it.
//  6. Prints the tool's text response to stdout.
//  7. Tears the task and container down cleanly.
//
// Every step that allocates external state (temp dir, task, container)
// installs its own cleanup; Run returns the first error it sees but
// always runs cleanups to completion so the host is left clean.
func Run(ctx context.Context, in RunInput) error {
	if err := validateRunInput(&in); err != nil {
		return err
	}

	// 1. Extract bundle.
	srcDir, err := os.MkdirTemp("", "agentcage-run-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	manifest, err := bundle.Extract(in.BundlePath, srcDir)
	if err != nil {
		return err
	}

	// Reparse the Agentfile from the materialized source so we get the
	// in-memory Agentfile struct the build path expects. The manifest's
	// AgentfileSpec is the wire format; deriving back to the struct
	// would mean carrying the conversion in two places.
	af, err := agentfile.ParseFile(filepath.Join(srcDir, "Agentfile"))
	if err != nil {
		return fmt.Errorf("re-parsing bundled Agentfile: %w", err)
	}

	// 2. Provisioner up. When the runtime is not yet provisioned
	//    (first run), show a phase-aware setup UI rather than dumping
	//    Lima's raw output at the operator. The UI is suppressed when
	//    the runtime is already ready, so subsequent runs show nothing
	//    here at all.
	provisioner, err := DefaultProvisioner()
	if err != nil {
		return err
	}
	defer func() { _ = provisioner.Close() }()

	if !SetupAlreadyReady(ctx, provisioner) {
		var ui = NewSetupUI(in.Stderr)
		if err := EnsureBootstrap(ctx, provisioner, ui, in.Verbose, in.Stderr); err != nil {
			return err
		}
	}

	// 3. Build the image via BuildKit. BuildKit's gRPC API is
	//    namespace-mount-agnostic, so this works through the
	//    forwarded socket without any of the cross-host snapshot
	//    pain that container lifecycle would hit.
	bk, err := DialBuildKit(ctx, provisioner.BuildKitAddress())
	if err != nil {
		return err
	}
	defer func() { _ = bk.Close() }()

	imageRef := deriveImageRef(in.BundlePath)
	if err := buildWithProgress(ctx, bk, BuildInput{
		Agentfile: af,
		Manifest:  manifest,
		SourceDir: srcDir,
		ImageRef:  imageRef,
	}, in.Stderr); err != nil {
		return err
	}

	// 4. Run the container via the provisioner. On macOS this enters
	//    the Lima VM's rootless mount namespace via `limactl shell
	//    agentcage nerdctl run`, sidestepping the namespace barrier
	//    the containerd Go client cannot cross from outside the VM.
	//    On Linux we shell out to nerdctl on the host directly.
	runID := in.RunID
	if runID == "" {
		runID = deriveRunID(in.BundlePath, manifest.FilesHash)
	}

	cmd := provisioner.PrepareRunContainer(ctx, runID, imageRef)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = in.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting container subprocess: %w", err)
	}

	// 5. MCP session over the subprocess's stdio.
	mcpClient, err := mcp.Connect(ctx, stdoutPipe, stdinPipe)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("MCP connect: %w", err)
	}
	defer func() { _ = mcpClient.Close() }()

	// 7. Call the tool. The CLI already resolved which one to use
	//    (run → manifest.Main; call → operator's explicit name).
	result, err := mcpClient.CallTool(ctx, in.Tool, in.Args)
	if err != nil {
		return err
	}

	// 8. Print result. Trailing newline only if the tool did not.
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	if _, err := io.WriteString(in.Stdout, result); err != nil {
		return fmt.Errorf("writing result: %w", err)
	}

	// 6. Tear down. Closing the MCP client closes stdin to the agent,
	//    which is the agent's signal to exit cleanly. nerdctl's --rm
	//    flag then removes the container. Wait reaps the subprocess
	//    so the host does not leak a zombie.
	_ = mcpClient.Close()
	_ = stdinPipe.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("container subprocess exited with error: %w", err)
	}

	return nil
}

// validateRunInput rejects calls that cannot reach the start of the
// flow. Fills defaults that the caller did not provide.
func validateRunInput(in *RunInput) error {
	if in.BundlePath == "" {
		return fmt.Errorf("RunInput.BundlePath is required")
	}
	if in.Tool == "" {
		return fmt.Errorf("RunInput.Tool is required (CLI must resolve main or pass an explicit tool name)")
	}
	if _, err := os.Stat(in.BundlePath); err != nil {
		return fmt.Errorf("bundle %s: %w", in.BundlePath, err)
	}
	if in.Stdout == nil {
		in.Stdout = os.Stdout
	}
	if in.Stderr == nil {
		in.Stderr = os.Stderr
	}
	if in.Args == nil {
		in.Args = map[string]any{}
	}
	return nil
}

// deriveImageRef turns a bundle path into the OCI image tag agentcage
// uses inside containerd's local image store. Stable across builds of
// the same agent (same basename → same ref), so re-running an agent
// reuses the BuildKit cache.
func deriveImageRef(bundlePath string) string {
	base := filepath.Base(bundlePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		base = "agent"
	}
	return "agentcage/" + sanitizeRef(base) + ":latest"
}

// deriveRunID names the containerd container for one run. Uniqueness
// across simultaneous runs comes from suffixing the bundle's content
// hash (the manifest's files_hash). Operators see this ID in
// `nerdctl ps` and trace tooling.
func deriveRunID(bundlePath, filesHash string) string {
	base := filepath.Base(bundlePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		base = "agent"
	}
	suffix := strings.TrimPrefix(filesHash, "sha256:")
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	if suffix == "" {
		suffix = "run"
	}
	return sanitizeRef(base) + "-" + suffix
}

// sanitizeRef converts a bundle basename into a fragment that is safe
// to use as an OCI ref component or a containerd container ID: ASCII
// letters, digits, dot, dash, underscore.
func sanitizeRef(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "agent"
	}
	return b.String()
}
