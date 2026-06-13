package main

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/reference"
	"github.com/okedeji/agentcage/internal/registry"
)

func newPushCmd() *cobra.Command {
	var bundlePath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "push REF [BUNDLE]",
		Short: "Push an agent bundle to an OCI registry",
		Long: `Push a built .agent bundle to an OCI registry.

REF is the agent reference. Shorthand (@org/name:version) resolves to the
default registry; a fully-qualified ref (ghcr.io/org/name:version) is taken
as written. Authentication reuses your Docker credentials, so a prior
'docker login' (or 'agentcage login') against the host is enough.

BUNDLE defaults to <name>.agent in the current directory, matching what
'agentcage build' writes.`,
		Example: `  agentcage push @okedeji/researcher:0.1
  agentcage push @okedeji/researcher:0.1 ./researcher.agent
  agentcage push ghcr.io/okedeji/researcher:0.1 -b out/researcher.agent`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := reference.Parse(args[0])
			if err != nil {
				return err
			}
			if ref.Tag == "" {
				return fmt.Errorf("push %s: a version tag is required (e.g. %s:0.1)", args[0], args[0])
			}

			path := bundlePath
			if len(args) > 1 {
				path = args[1]
			}
			if path == "" {
				path = defaultBundleForRef(ref)
			}

			client, err := registry.New()
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if !jsonOut {
				_, _ = fmt.Fprintf(w, "Pushing %s to %s/%s\n", path, ref.Registry, ref.Repository)
			}
			digest, err := client.Push(cmd.Context(), ref, path)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(w).Encode(map[string]string{
					"ref":    ref.OCIRef(),
					"tag":    ref.Tag,
					"digest": digest,
				})
			}
			_, _ = fmt.Fprintf(w, "%s: digest: %s\n", ref.Tag, digest)
			return nil
		},
	}
	cmd.Flags().StringVarP(&bundlePath, "bundle", "b", "", "path to the .agent file (default <name>.agent)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return cmd
}

// defaultBundleForRef derives the .agent filename 'agentcage build' would
// have written for this reference: the last path component of the
// repository plus .agent. ghcr.io/okedeji/researcher -> researcher.agent.
func defaultBundleForRef(ref reference.Reference) string {
	name := path.Base(ref.Repository)
	if name == "" || name == "." || name == "/" {
		name = "agent"
	}
	return strings.TrimSuffix(name, ".agent") + ".agent"
}
