package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/okedeji/agentcage/internal/agentfile"
	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/mcp"
	"github.com/okedeji/agentcage/internal/reference"
	"github.com/okedeji/agentcage/internal/registry"
)

// containerStopTimeout bounds how long teardown waits for one detached
// container or network to go away. nerdctl SIGTERMs then escalates to
// SIGKILL after its own 10s; 30s leaves room for that plus the limactl
// shell round-trip into the VM. Exceeding it abandons the container to the
// next stray-resource sweep rather than hanging the operator's shutdown.
const containerStopTimeout = 30 * time.Second

// bootRun picks the boot path by whether the agent declares any USES: no
// dependencies takes today's single-container path unchanged; one or more
// takes the tree path that starts every sub-agent behind the gateway.
func bootRun(ctx context.Context, in RunInput, boot bootInput, runID string) (*mcp.Client, func() error, error) {
	if len(boot.Manifest.Agentfile.Uses) == 0 {
		return bootAgent(ctx, boot)
	}

	tree, err := resolveRunTree(ctx, runID, in.BundlePath, boot.Manifest)
	if err != nil {
		return nil, nil, err
	}
	plan, err := buildRunPlan(tree, runID)
	if err != nil {
		return nil, nil, err
	}
	return bootTree(ctx, boot, plan)
}

// resolveRunTree walks the root's transitive USES graph, pulling each
// dependency from the registry by its locked digest.
func resolveRunTree(ctx context.Context, runID, rootBundle string, root *bundle.Manifest) (*runTree, error) {
	reg, err := registry.New()
	if err != nil {
		return nil, fmt.Errorf("registry client: %w", err)
	}
	pull := func(ctx context.Context, ref reference.Reference) (string, *bundle.Manifest, error) {
		path, _, err := reg.Pull(ctx, ref)
		if err != nil {
			return "", nil, err
		}
		m, err := bundle.ReadManifest(path)
		if err != nil {
			return "", nil, fmt.Errorf("reading pulled manifest %s: %w", ref.OCIRef(), err)
		}
		return path, m, nil
	}
	return resolveTree(ctx, runID, rootBundle, root, pull)
}

// bootTree starts a parent whose bundle has USES dependencies: a per-run
// network, every sub-agent detached and serving HTTP on it, the gateway
// carrying the routing table, and finally the root parent attached over
// stdio with its sub-agent URLs. The order matters: the network exists
// before anything joins it, and the root boots last so the gateway and
// sub-agents it calls are already listening. Teardown reverses all of it.
func bootTree(ctx context.Context, in bootInput, plan *runPlan) (*mcp.Client, func() error, error) {
	td := &teardown{}
	booted := false
	defer func() {
		if !booted {
			_ = td.run()
		}
	}()

	sess, err := newBootSession(ctx, in, td)
	if err != nil {
		return nil, nil, err
	}

	if err := createNetwork(ctx, sess.provisioner, plan.Network); err != nil {
		return nil, nil, err
	}
	td.push(func() error { return removeNetwork(sess.provisioner, plan.Network) })

	for _, a := range plan.Agents {
		if err := buildAgentImage(ctx, sess.bk, a.Node, a.Spec.ImageRef, in.Stderr); err != nil {
			return nil, nil, err
		}
		if err := startDetached(ctx, sess.provisioner, a.Spec); err != nil {
			return nil, nil, err
		}
		name := a.Spec.RunID
		td.push(func() error { return stopContainer(sess.provisioner, name) })
	}

	// The gateway is the only host the parent's USES URLs resolve to, so it
	// sees every call in the tree and enforces every edge's deny.
	if err := BuildGatewayImage(ctx, sess.bk, in.Stderr); err != nil {
		return nil, nil, err
	}
	if err := startDetached(ctx, sess.provisioner, plan.Gateway); err != nil {
		return nil, nil, err
	}
	td.push(func() error { return stopContainer(sess.provisioner, plan.Gateway.RunID) })

	in.Network = plan.Network
	in.Env = plan.RootEnv
	client, err := startAttachedAgent(ctx, sess, in, td)
	if err != nil {
		return nil, nil, err
	}

	booted = true
	return client, td.run, nil
}

// buildAgentImage extracts a sub-agent's bundle to a temp dir, reparses its
// Agentfile, and builds its image. The source is only needed during the
// build, so it is removed as soon as the image lands in containerd.
func buildAgentImage(ctx context.Context, bk *BuildKit, node *agentNode, imageRef string, stderr io.Writer) error {
	srcDir, err := os.MkdirTemp("", "agentcage-sub-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	manifest, err := bundle.Extract(node.Bundle, srcDir)
	if err != nil {
		return fmt.Errorf("extracting %s: %w", node.Key, err)
	}
	af, err := agentfile.ParseFile(filepath.Join(srcDir, "Agentfile"))
	if err != nil {
		return fmt.Errorf("re-parsing %s Agentfile: %w", node.Key, err)
	}
	return buildWithProgress(ctx, bk, BuildInput{
		Agentfile: af,
		Manifest:  manifest,
		SourceDir: srcDir,
		ImageRef:  imageRef,
	}, stderr)
}

func createNetwork(ctx context.Context, p Provisioner, name string) error {
	return runNerdctl(p.Nerdctl(ctx, "network", "create", name), "creating network "+name)
}

func startDetached(ctx context.Context, p Provisioner, spec ContainerSpec) error {
	return runNerdctl(p.Nerdctl(ctx, nerdctlRunArgs(spec)...), "starting "+spec.RunID)
}

// removeNetwork and stopContainer run at teardown on a fresh context: the
// boot context may already be cancelled (operator Ctrl-C) and the resources
// still have to come down. The deadline keeps a wedged stop from hanging
// shutdown.
func removeNetwork(p Provisioner, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), containerStopTimeout)
	defer cancel()
	return runNerdctl(p.Nerdctl(ctx, "network", "rm", name), "removing network "+name)
}

func stopContainer(p Provisioner, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), containerStopTimeout)
	defer cancel()
	return runNerdctl(p.Nerdctl(ctx, "stop", name), "stopping "+name)
}

// runNerdctl runs a nerdctl command, discarding stdout and folding captured
// stderr into the error so a failed network or container op says why.
func runNerdctl(cmd *exec.Cmd, action string) error {
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s: %w: %s", action, err, msg)
		}
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}
