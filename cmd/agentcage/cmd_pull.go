package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/reference"
	"github.com/okedeji/agentcage/internal/registry"
)

func newPullCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "pull REF",
		Short: "Pull an agent bundle from an OCI registry",
		Long: `Pull an agent bundle from an OCI registry into the local cache.

REF accepts the same forms as 'push': shorthand (@org/name:version) or a
fully-qualified host ref. A ref pinned to a digest that is already cached
returns without touching the network.

The bundle lands under ~/.agentcage/cache and the cache path is printed so
it can be fed to 'agentcage run' or 'agentcage call'.`,
		Example: `  agentcage pull @anthropic/web-search:1.2.0
  agentcage pull ghcr.io/okedeji/researcher:0.1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := reference.Parse(args[0])
			if err != nil {
				return err
			}
			if ref.Tag == "" && ref.Digest == "" {
				return fmt.Errorf("pull %s: a version tag or digest is required (e.g. %s:1.2.0)", args[0], args[0])
			}

			client, err := registry.New()
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			target := ref.Tag
			if target == "" {
				target = ref.Digest
			}
			if !jsonOut {
				_, _ = fmt.Fprintf(w, "%s: Pulling from %s/%s\n", target, ref.Registry, ref.Repository)
			}

			bundlePath, digest, err := client.Pull(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(w).Encode(map[string]string{
					"ref":    ref.OCIRef(),
					"digest": digest,
					"path":   bundlePath,
				})
			}
			_, _ = fmt.Fprintf(w, "Digest: %s\n", digest)
			_, _ = fmt.Fprintf(w, "Status: Downloaded bundle for %s\n", ref.OCIRef())
			_, _ = fmt.Fprintln(w, bundlePath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return cmd
}
