package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/bundle"
	"github.com/okedeji/mcpvessel/internal/eval"
	"github.com/okedeji/mcpvessel/internal/reference"
	"github.com/okedeji/mcpvessel/internal/registry"
	"github.com/okedeji/mcpvessel/internal/signing"
	"github.com/okedeji/mcpvessel/internal/store"
)

func newPushCmd() *cobra.Command {
	var bundlePath string
	var jsonOut bool
	var withEvals bool
	var judgeModel string
	var forcePublic, forcePrivate bool
	var registryName string
	var noSign bool
	cmd := &cobra.Command{
		Use:   "push REF [BUNDLE]",
		Short: "Push an agent bundle to an OCI registry",
		Long: `Push a built .agent bundle to an OCI registry.

REF is the agent reference. Shorthand (@org/name:version) resolves to the
default registry; a fully-qualified ref (ghcr.io/org/name:version) is taken
as written. Authentication reuses your stored OCI registry credentials, so a
prior 'mcpvessel login' against the host (or any login that wrote to the shared
credential store) is enough.

The bundle comes from the local store: 'mcpvessel build -t REF' put it there,
and push reads it back by REF. Pass an explicit bundle path (positional or -b)
to push a file built elsewhere or with -o.

push signs the digest with this host's key, generated on first use; pulls
verify it and pin your key. Keep one key across machines ('mcpvessel keys
export'). --no-sign skips signing.`,
		Example: `  mcpvessel push @okedeji/researcher:0.1
  mcpvessel push @okedeji/researcher:0.1 ./researcher.agent
  mcpvessel push ghcr.io/okedeji/researcher:0.1 -b out/researcher.agent`,
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
				path, err = bundleFromStore(ref, args[0])
				if err != nil {
					return err
				}
			}

			// Decide and log in before the upload: an unpublishable push fails
			// early, and the short-lived registry token is minted just before use.
			doPublish, err := preparePublish(cmd, ref, forcePublic, forcePrivate)
			if err != nil {
				return err
			}

			client, err := registry.New()
			if err != nil {
				return err
			}

			if withEvals {
				if err := stampEvalsBeforePush(cmd.Context(), cmd.ErrOrStderr(), args[0], path, judgeModel); err != nil {
					return err
				}
			}

			w := cmd.OutOrStdout()
			if !jsonOut {
				_, _ = fmt.Fprintf(w, "Pushing %s to %s/%s\n", path, ref.Registry, ref.Repository)
			}
			digest, err := client.Push(cmd.Context(), ref, path)
			if err != nil {
				return err
			}

			// Publish only after the OCI artifact is up, so a failed publish
			// never leaves a registry entry with no bundle behind it. The bytes
			// are already pushed, so only an explicit --public fails the push.
			noteW := w
			if jsonOut {
				noteW = cmd.ErrOrStderr()
			}

			var keyFingerprint string
			if !noSign {
				keyFingerprint, err = signAfterPush(cmd.Context(), noteW, client, ref, digest)
				if err != nil {
					return fmt.Errorf("%w (the bundle is pushed; --no-sign pushes without a signature)", err)
				}
			}
			if doPublish {
				if err := publishToRegistry(cmd.Context(), noteW, ref, path, registryName); err != nil {
					if forcePublic {
						return err
					}
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: pushed to OCI but MCP Registry publish failed: %v\n", err)
				}
			}

			if jsonOut {
				out := map[string]string{
					"ref":    ref.OCIRef(),
					"tag":    ref.Tag,
					"digest": digest,
				}
				if keyFingerprint != "" {
					out["signing_key"] = keyFingerprint
				}
				return json.NewEncoder(w).Encode(out)
			}
			_, _ = fmt.Fprintf(w, "%s: digest: %s\n", ref.Tag, digest)
			return nil
		},
	}
	cmd.Flags().StringVarP(&bundlePath, "bundle", "b", "", "path to a .agent file (default: read from the store by ref)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	cmd.Flags().BoolVar(&withEvals, "with-evals", false, "run the eval suite and record the results into the manifest before pushing")
	cmd.Flags().StringVar(&judgeModel, "judge-model", "", "provider/model to grade judged cases (default: your default provider)")
	cmd.Flags().BoolVar(&forcePublic, "public", false, "publish to the MCP Registry even when the host is not auto-detected as public")
	cmd.Flags().BoolVar(&forcePrivate, "private", false, "skip MCP Registry publication even on a public host")
	cmd.Flags().StringVar(&registryName, "name", "", "MCP Registry name to publish under (default: io.github.<owner>/<name> from a GHCR ref)")
	cmd.Flags().BoolVar(&noSign, "no-sign", false, "push without signing (pulls will report the bundle unsigned)")
	return cmd
}

// signAfterPush signs the pushed digest and uploads the signature next to the
// bundle, returning the key fingerprint. Signing failure fails the push
// command: a --sign the operator asked for must not silently not happen.
func signAfterPush(ctx context.Context, w io.Writer, client *registry.Client, ref reference.Reference, digest string) (string, error) {
	key, created, err := signing.EnsureKey()
	if err != nil {
		return "", err
	}
	fp := signing.Fingerprint(signing.PublicKeyEncoded(key.Public))
	if created {
		path, _ := signing.KeyPath()
		_, _ = fmt.Fprintf(w, "Generated signing key %s at %s (back it up; 'mcpvessel keys' shows the public half)\n", fp, path)
	}
	sig, err := signing.Sign(key, digest, ref.Registry+"/"+ref.Repository)
	if err != nil {
		return "", err
	}
	if err := client.PushSignature(ctx, ref, digest, sig); err != nil {
		return "", err
	}
	_, _ = fmt.Fprintf(w, "Signed: key %s\n", fp)
	return fp, nil
}

// stampEvalsBeforePush runs the eval suite against the resolved bundle path
// (a -b bundle not indexed in the store still evaluates) and records the
// results into the manifest. Failing cases do not block the push: the stamp
// is a transparency signal, not a gate.
func stampEvalsBeforePush(ctx context.Context, w io.Writer, displayRef, bundlePath, judgeModel string) error {
	manifest, err := bundle.ReadManifest(bundlePath)
	if err != nil {
		return err
	}
	if manifest.Vesselfile.Eval == "" {
		return fmt.Errorf("--with-evals: bundle %s declares no EVAL suite", displayRef)
	}
	data, err := bundle.ReadSourceFile(bundlePath, manifest.Vesselfile.Eval)
	if err != nil {
		return err
	}
	suite, err := eval.LoadSuite(data)
	if err != nil {
		return err
	}

	report, err := runSuiteForBundle(ctx, suiteParams{
		ref:        bundlePath,
		manifest:   manifest,
		suite:      suite,
		judgeModel: judgeModel,
		results:    w,
		logs:       w,
	})
	if err != nil {
		return err
	}
	printSummary(w, displayRef, report)

	if err := eval.Stamp(bundlePath, report, time.Now()); err != nil {
		return fmt.Errorf("recording eval results: %w", err)
	}
	if report.Failed > 0 {
		_, _ = fmt.Fprintf(w, "warning: %d of %d cases failed; pushing anyway\n", report.Failed, report.Passed+report.Failed)
	}
	return nil
}

// bundleFromStore locates the stored bundle for ref; arg is the operator's
// original spelling, used in the error message.
func bundleFromStore(ref reference.Reference, arg string) (string, error) {
	st, err := store.New()
	if err != nil {
		return "", err
	}
	path, ok, err := st.Get(ref)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("push %s: no bundle in the store for this ref; run 'mcpvessel build -t %s' first, or pass a bundle path", arg, arg)
	}
	return path, nil
}
