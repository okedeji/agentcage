package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/bundle"
	"github.com/okedeji/agentcage/internal/runtime"
)

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run BUNDLE [PROMPT]",
		Short: "Run an agent (routes the prompt to its MAIN tool)",
		Long: `Run an agent and print its response.

The bundle is the .agent file produced by 'agentcage build'. agentcage
extracts it, makes sure the runtime is ready (provisioning a Linux VM
on macOS the first time), builds the agent's image, starts a container,
and routes the prompt to the tool the Agentfile declared as MAIN.

What MAIN does inside its function body is the author's call: typically
its LLM reasons about the prompt, calls sub-agents, calls its own
tools, and returns a synthesized response — but any other shape is
fine. The platform just routes the prompt to MAIN and prints whatever
comes back.

For bundles without MAIN — tool collections that expose named tools
without designating one as the bundle's "talk to me" entry — use
'agentcage call BUNDLE TOOL' to invoke a tool by name.

Examples:

  agentcage run hello.agent
  agentcage run researcher.agent "summarize Q3 earnings"`,
		Example: `  agentcage run hello.agent
  agentcage run researcher.agent "summarize Q3 earnings"`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := args[0]
			prompt := ""
			if len(args) > 1 {
				prompt = args[1]
			}

			manifest, err := bundle.ReadManifest(bundlePath)
			if err != nil {
				return err
			}
			if manifest.Agentfile.Main == "" {
				return fmt.Errorf("bundle %s has no MAIN — it is a tool collection. Use 'agentcage call %s TOOL --arg KEY=VALUE' to call one of its tools directly", bundlePath, bundlePath)
			}

			toolArgs := map[string]any{}
			if prompt != "" {
				toolArgs["prompt"] = prompt
			}
			return runtime.Run(cmd.Context(), runtime.RunInput{
				BundlePath: bundlePath,
				Tool:       manifest.Agentfile.Main,
				Args:       toolArgs,
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	return cmd
}
