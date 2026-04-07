package grpc

import (
	"context"
	"fmt"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// WaitForReady polls Ping on the orchestrator's own gRPC endpoint until it
// succeeds or ctx expires. Used by the init flow to gate the "ready" banner
// so it only prints when the server is actually dispatching, and by the
// platform-specific helpers to wait for an embedded VM's services.
func WaitForReady(ctx context.Context, addr string) error {
	start := time.Now()
	lastReport := start
	for {
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
			client := pb.NewControlServiceClient(conn)
			_, pingErr := client.Ping(pingCtx, &pb.PingRequest{})
			pingCancel()
			_ = conn.Close()
			if pingErr == nil {
				return nil
			}
		}

		if time.Since(lastReport) >= 10*time.Second {
			fmt.Printf("  Still waiting for services... (%ds elapsed)\n", int(time.Since(start).Seconds()))
			lastReport = time.Now()
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for gRPC readiness at %s", addr)
		case <-time.After(2 * time.Second):
		}
	}
}
