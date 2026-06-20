package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/daemon"
)

func newStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop RUN",
		Short: "Stop a running agent",
		Long: `Stop a running agent and release its containers and networks.

RUN is the run id 'agentcage ps' lists. stop talks to the daemon, so it needs
one running.`,
		Example: `  agentcage stop researcher-7a1c4f2e9d3b`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			socket, err := daemon.SocketPath()
			if err != nil {
				return err
			}
			if err := daemon.Dial(socket).StopRun(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("%w (is the daemon running?)", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), args[0])
			return nil
		},
	}
	return cmd
}
