package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/bundle"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	bundle.SetBuiltWith("agentcage " + version)

	root := &cobra.Command{
		Use:           "agentcage",
		Short:         "Build, ship, and run agents",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newBuildCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
