package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/bundle"
)

func newBuildCmd() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "build [PATH]",
		Short: "Build an agent bundle from an Agentfile",
		Long: `Build an agent bundle from a directory containing an Agentfile and source.

The directory defaults to the current directory. The output is a .agent file
named after the source directory unless -o is given.`,
		Example: `  agentcage build .
  agentcage build ./my-agent
  agentcage build . -o my-agent.agent`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcDir := "."
			if len(args) > 0 {
				srcDir = args[0]
			}
			if outPath == "" {
				outPath = defaultOutputPath(srcDir)
			}
			return runBuild(cmd.OutOrStdout(), srcDir, outPath)
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output path for the .agent file")
	return cmd
}

// runBuild calls bundle.Build with progress lines written to w.
// w is taken from the cobra command so tests and callers that want the
// output captured (e.g. for --json later) can override it.
//
// Output mirrors Docker's classic builder shape:
//
//	Step 1/3 : Parsing Agentfile
//	Step 2/3 : Hashing source tree
//	Step 3/3 : Sealing bundle → my-agent.agent
//	Successfully built my-agent.agent (608 B) in 12ms
func runBuild(w io.Writer, srcDir, outPath string) error {
	start := time.Now()

	err := bundle.Build(srcDir, outPath, bundle.WithProgress(func(step, total int, msg string) {
		_, _ = fmt.Fprintf(w, "Step %d/%d : %s\n", step, total, msg)
	}))
	if err != nil {
		return err
	}

	size := "?"
	if info, statErr := os.Stat(outPath); statErr == nil {
		size = humanSize(info.Size())
	}
	_, _ = fmt.Fprintf(w, "Successfully built %s (%s) in %s\n",
		outPath, size, time.Since(start).Round(time.Millisecond))
	return nil
}

// defaultOutputPath derives a .agent filename from the source directory's
// basename. "." resolves to the cwd's basename so `agentcage build .` in
// /Users/x/researcher writes ./researcher.agent.
func defaultOutputPath(srcDir string) string {
	abs, err := filepath.Abs(srcDir)
	if err != nil {
		// Fall back to a generic name; the build itself will surface the
		// real error if there is one.
		return "agent.agent"
	}
	return filepath.Base(abs) + ".agent"
}

// humanSize formats n bytes in the smallest binary unit that keeps the
// number above 1, matching how Docker reports image sizes.
func humanSize(n int64) string {
	const (
		kb = 1 << 10
		mb = 1 << 20
		gb = 1 << 30
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(kb))
	}
	return fmt.Sprintf("%d B", n)
}
