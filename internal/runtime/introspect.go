package runtime

import (
	"context"
	"io"

	"github.com/okedeji/agentcage/internal/agentfile"
	"github.com/okedeji/agentcage/internal/mcp"
)

// IntrospectInput drives Introspect. ImageRef should be the same ref the
// later run derives (deriveImageRef of the bundle), so the image this
// builds is reused rather than rebuilt at run time.
type IntrospectInput struct {
	Agentfile *agentfile.Agentfile
	SourceDir string
	ImageRef  string
	Stdout    io.Writer
	Stderr    io.Writer
	Verbose   bool
}

// Introspect builds the agent's image, boots it, and returns the tools its
// MCP server advertises. It is metadata-only: it lists tools and never
// calls one, so no tool body runs and the agent's LLM is never invoked.
// The only thing that executes is the agent's own server startup.
func Introspect(ctx context.Context, in IntrospectInput) ([]mcp.Tool, error) {
	client, teardown, err := bootAgent(ctx, bootInput{
		Agentfile: in.Agentfile,
		// Labels are provenance only and the authoritative manifest is
		// sealed later by the bundle build, so a nil manifest is fine here.
		Manifest:  nil,
		SourceDir: in.SourceDir,
		ImageRef:  in.ImageRef,
		RunID:     introspectRunID(in.ImageRef),
		Stdout:    in.Stdout,
		Stderr:    in.Stderr,
		Verbose:   in.Verbose,
	})
	if err != nil {
		return nil, err
	}

	tools, err := client.ListTools(ctx)
	if err != nil {
		_ = teardown()
		return nil, err
	}
	if err := teardown(); err != nil {
		return nil, err
	}
	return tools, nil
}

// introspectRunID names the short-lived introspection container. Distinct
// from a run's container name so an introspection and a run of the same
// agent do not collide.
func introspectRunID(imageRef string) string {
	return sanitizeRef(imageRef) + "-introspect"
}
