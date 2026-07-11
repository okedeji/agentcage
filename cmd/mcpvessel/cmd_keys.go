package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/okedeji/mcpvessel/internal/signing"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Show this host's bundle signing key",
		Long: `Show the public half of the key push signs with, generating the keypair on
first use.

The private key stays in ~/.mcpvessel/signing-key.json (0600) and never leaves
this host. Publish the fingerprint somewhere pullers can check (your README,
your MCP Registry entry) so a first pull pins the right key.`,
		Example: `  mcpvessel keys`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			key, created, err := signing.EnsureKey()
			if err != nil {
				return err
			}
			pub := signing.PublicKeyEncoded(key.Public)
			path, err := signing.KeyPath()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if created {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Generated a new signing key")
			}
			_, _ = fmt.Fprintf(w, "Fingerprint: %s\n", signing.Fingerprint(pub))
			_, _ = fmt.Fprintf(w, "Public key:  %s\n", pub)
			_, _ = fmt.Fprintf(w, "Path:        %s\n", path)
			return nil
		},
	}
	cmd.AddCommand(newKeysExportCmd(), newKeysImportCmd())
	return cmd
}

func newKeysExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Write the signing key to stdout, for backup or another machine",
		Long: `Write the private signing key to stdout so a laptop and CI can sign as the
same publisher, or so the key survives this machine.

Redirect it; a terminal is refused so the key never lands in scrollback.`,
		Example: `  mcpvessel keys export > mcpvessel-signing.key
  mcpvessel keys export | ssh ci 'mcpvessel keys import'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f, ok := cmd.OutOrStdout().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				return fmt.Errorf("refusing to print a private key to a terminal; redirect it: mcpvessel keys export > mcpvessel-signing.key")
			}
			raw, err := signing.ExportKey()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(raw)
			return err
		},
	}
}

func newKeysImportCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Install a signing key exported from another machine, read from stdin",
		Long: `Install an exported signing key so this machine signs as the same publisher.

The key is read from stdin, never an argument, so it stays out of shell
history and the process table. Importing the key already installed is a no-op;
a different key needs --force.`,
		Example: `  mcpvessel keys import < mcpvessel-signing.key`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("reading key from stdin: %w", err)
			}
			key, err := signing.ImportKey(raw, force)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Imported signing key %s\n", signing.Fingerprint(signing.PublicKeyEncoded(key.Public)))
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing different key")
	return cmd
}

func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage pinned publisher signing keys",
		Long: `List and remove the publisher keys this host has pinned.

A publisher's key is pinned the first time a signed bundle of theirs is pulled
(SSH known_hosts semantics). Every later pull from that scope must be signed by
the same key; a different key fails closed. Remove a pin only after verifying
the publisher's new key out of band.`,
	}

	ls := &cobra.Command{
		Use:   "ls",
		Short: "List pinned publisher keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			trust, err := signing.LoadTrust()
			if err != nil {
				return err
			}
			scopes := trust.Scopes()
			if len(scopes) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No pinned keys. A key is pinned on the first pull of a signed bundle.")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 8, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "SCOPE\tKEY\tPINNED")
			for _, s := range scopes {
				pin, _ := trust.Get(s)
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s, signing.Fingerprint(pin.PublicKey), pin.PinnedAt.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}

	rm := &cobra.Command{
		Use:   "rm SCOPE",
		Short: "Remove a pinned key so the next signed pull re-pins",
		Example: `  mcpvessel trust ls
  mcpvessel trust rm ghcr.io/okedeji`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			trust, err := signing.LoadTrust()
			if err != nil {
				return err
			}
			if !trust.Remove(args[0]) {
				return fmt.Errorf("no pinned key for %s; 'mcpvessel trust ls' shows what is pinned", args[0])
			}
			if err := trust.Save(); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed pin for %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(ls, rm)
	return cmd
}
