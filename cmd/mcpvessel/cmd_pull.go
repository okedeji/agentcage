package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/locate"
	"github.com/okedeji/mcpvessel/internal/reference"
	"github.com/okedeji/mcpvessel/internal/registry"
)

func newPullCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "pull REF",
		Short: "Pull an agent bundle from an OCI registry",
		Long: `Pull an agent bundle from an OCI registry into the local cache.

REF accepts the same forms as 'push': shorthand (@org/name:version) or a
fully-qualified host ref. An MCP Registry name (io.github.user/server) also
works, the same resolution 'run' and 'serve' do: the entry's OCI artifact is
pulled, at the entry's version or a :version you append. A ref pinned to a
digest that is already cached returns without touching the network.

The bundle lands under ~/.mcpvessel/cache and the cache path is printed so
it can be fed to 'mcpvessel run' or 'mcpvessel call'.`,
		Example: `  mcpvessel pull @anthropic/web-search:1.2.0
  mcpvessel pull ghcr.io/okedeji/researcher:0.1
  mcpvessel pull io.github.okedeji/mcpvessel-docs`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg, err := resolveRegistryNameArg(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			ref, err := reference.Parse(arg)
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
			client.Notify = func(format string, args ...any) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...)
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

// resolveRegistryNameArg resolves an MCP Registry name (io.github.user/server,
// optionally with a trailing :version) to the OCI ref its registry entry
// points at. Anything that is not a registry name passes through untouched
// for the ordinary reference parser.
func resolveRegistryNameArg(ctx context.Context, arg string) (string, error) {
	nameArg, tag := arg, ""
	if i := strings.LastIndex(arg, ":"); i > strings.LastIndex(arg, "/") {
		nameArg, tag = arg[:i], arg[i+1:]
	}
	name, ok := locate.RegistryName(nameArg)
	if !ok {
		return arg, nil
	}
	resolved, err := locate.ResolveRegistryName(ctx, name)
	if err != nil {
		return "", err
	}
	// A :version the operator appended pins that version on the resolved
	// repository, overriding the version the registry entry advertises.
	if tag != "" {
		r, perr := reference.Parse(resolved)
		if perr != nil {
			return "", perr
		}
		r.Tag, r.Digest = tag, ""
		resolved = r.OCIRef()
	}
	return resolved, nil
}
