package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/bundle"
	"github.com/okedeji/mcpvessel/internal/config"
	"github.com/okedeji/mcpvessel/internal/env"
	"github.com/okedeji/mcpvessel/internal/mcpregistry"
	"github.com/okedeji/mcpvessel/internal/reference"
	"github.com/okedeji/mcpvessel/internal/registry"
)

func newRegisterCmd() *cobra.Command {
	var bundlePath, name string
	cmd := &cobra.Command{
		Use:   "register REF [BUNDLE]",
		Short: "Publish an already-pushed agent to the MCP Registry",
		Long: `Publish a public agent's metadata to the MCP Registry without re-pushing it.

register is for an artifact already on a public OCI host: 'mcpvessel push' does
this automatically, but register lets you publish (or re-publish) on its own, for
an agent pushed before you logged in to the registry or one whose OCI bytes have
not changed.

The reverse-DNS name defaults to io.github.<owner>/<name> derived from a GHCR
ref; pass --name to publish under a different namespace. Requires a prior
'mcpvessel login mcp-registry'.`,
		Example: `  mcpvessel register ghcr.io/okedeji/researcher:0.1
  mcpvessel register @okedeji/researcher:0.1 --name io.github.okedeji/researcher`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := reference.Parse(args[0])
			if err != nil {
				return err
			}
			if ref.Tag == "" {
				return fmt.Errorf("register %s: a version tag is required (e.g. %s:0.1)", args[0], args[0])
			}
			path := bundlePath
			if len(args) > 1 {
				path = args[1]
			}
			if path == "" {
				path, err = bundleFromStore(ref, args[0])
				if err != nil {
					return err
				}
			}
			// A missing login is an offer to log in, not a silent skip.
			if _, err := confirmLoginIfNeeded(cmd, true); err != nil {
				return err
			}
			return publishToRegistry(cmd.Context(), cmd.OutOrStdout(), ref, path, name)
		},
	}
	cmd.Flags().StringVarP(&bundlePath, "bundle", "b", "", "path to a .agent file (default: read from the store by ref)")
	cmd.Flags().StringVar(&name, "name", "", "MCP Registry name to publish under (default: io.github.<owner>/<name> from a GHCR ref)")
	return cmd
}

// publishToRegistry records a pushed bundle's server.json in the MCP Registry,
// gated on the OCI artifact being publicly pullable.
func publishToRegistry(ctx context.Context, w io.Writer, ref reference.Reference, bundlePath, nameOverride string) error {
	return publishToRegistryWith(ctx, w, ref, bundlePath, nameOverride, registry.ResolvePublic)
}

// publishToRegistryWith is publishToRegistry with the public-artifact check
// injected for tests. A ref with no derivable reverse-DNS name errors rather
// than publishing under a guessed namespace.
func publishToRegistryWith(ctx context.Context, w io.Writer, ref reference.Reference, bundlePath, nameOverride string, verifyPublic func(context.Context, reference.Reference) (string, error)) error {
	name := nameOverride
	if name == "" {
		derived, ok := ref.ReverseDNSName()
		if !ok {
			return fmt.Errorf("cannot derive a reverse-DNS name for %s; pass --name io.github.<user>/<server>", ref.OCIRef())
		}
		name = derived
	}

	token, found, err := mcpregistry.LoadToken()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("not logged in to the MCP Registry; run 'mcpvessel login mcp-registry' first")
	}

	// The registry indexes metadata only; refuse to advertise a bundle that is
	// not pushed and anonymously pullable, rather than publish a dangling pointer.
	if _, err := verifyPublic(ctx, ref); err != nil {
		return fmt.Errorf("cannot publish %s: its bundle is not pushed to a public OCI host (run 'mcpvessel push' first, and make the package public): %w", name, err)
	}

	manifest, err := bundle.ReadManifest(bundlePath)
	if err != nil {
		return err
	}
	server := mcpregistry.ServerJSONFromManifest(*manifest, name, ref.Registry+"/"+ref.Repository, ref.Tag)
	if err := mcpregistry.New().Publish(ctx, server, token.Value); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Published %s to the MCP Registry\n", name)
	return nil
}

// publishDecision decides whether a push also attempts to publish: operator
// flags win, else a public host attempts and a private host skips. Visibility
// is not confirmed here; publishToRegistry is the real gate. An empty reason
// with publish=false means the operator asked for --private.
func publishDecision(host string, forcePublic, forcePrivate bool) (publish bool, reason string) {
	switch {
	case forcePrivate:
		return false, ""
	case forcePublic:
		return true, ""
	case reference.IsPublicHost(host):
		return true, ""
	default:
		return false, "private OCI host"
	}
}

// preparePublish is push's pre-flight: it decides before the OCI upload whether
// this push will publish, and gets the operator logged in when they want to.
// False means push-only; an error means the operator aborted.
func preparePublish(cmd *cobra.Command, ref reference.Reference, forcePublic, forcePrivate bool) (bool, error) {
	publish, reason := publishDecision(ref.Registry, forcePublic, forcePrivate)
	if !publish {
		if reason != "" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "note: skipping MCP Registry publish (%s)\n", reason)
		}
		return false, nil
	}
	return confirmLoginIfNeeded(cmd, forcePublic)
}

// confirmLoginIfNeeded ensures a live registry token, offering an interactive
// operator the login. mustPublish (register, or push --public) turns a missing
// app or a non-interactive session into an error rather than a silent skip. A
// non-interactive session never prompts: publish if logged in, else skip with
// a note.
func confirmLoginIfNeeded(cmd *cobra.Command, mustPublish bool) (bool, error) {
	tok, found, tokErr := mcpregistry.LoadToken()
	if tokErr == nil && found && !tok.Expired() {
		return true, nil
	}
	// A token that exists but lapsed is an expired login, not a missing app:
	// registry tokens live minutes, so this is the common case, and naming a
	// client id here would send the operator configuring the wrong thing.
	expired := tokErr == nil && found

	interactive := isInteractive(cmd)

	if config.LookupEnv(env.GitHubClientID) == "" {
		how := "no MCP Registry app configured; set one with 'mcpvessel config env set VESSEL_GITHUB_CLIENT_ID <client-id>'"
		if expired {
			how = "your MCP Registry login has expired (registry tokens are short-lived); run 'mcpvessel login mcp-registry' again"
		}
		if mustPublish {
			return false, fmt.Errorf("cannot publish: %s", how)
		}
		if interactive && !confirm(cmd, "This public agent will not be published ("+how+"). Push anyway?") {
			return false, fmt.Errorf("aborted; %s", how)
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "note: not publishing (%s)\n", how)
		return false, nil
	}

	if !interactive {
		if mustPublish {
			return false, fmt.Errorf("cannot publish: not logged in to the MCP Registry; run 'mcpvessel login mcp-registry' first")
		}
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "note: not publishing (not logged in; run 'mcpvessel login mcp-registry' then 'mcpvessel register')")
		return false, nil
	}

	if !mustPublish && !confirm(cmd, "Not logged in to the MCP Registry. Log in now to publish this public agent?") {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Pushing without publishing; run 'mcpvessel register <ref>' later to publish.")
		return false, nil
	}
	if err := loginMCPRegistry(cmd, "", false); err != nil {
		return false, err
	}
	return true, nil
}
