package grpc

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var ProxyTarget = config.DefaultGRPCAddr

// Proxy dials the gRPC server and dispatches the command.
func Proxy(cmd string, args []string) {
	conn, err := grpc.NewClient(ProxyTarget,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running. Run 'agentcage init' first.")
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	control := pb.NewControlServiceClient(conn)
	if _, err := control.Ping(ctx, &pb.PingRequest{}); err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running. Run 'agentcage init' first.")
		os.Exit(1)
	}

	switch cmd {
	case "fleet":
		proxyFleet(conn, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func proxyFleet(conn *grpc.ClientConn, _ []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewFleetServiceClient(conn)
	resp, err := client.GetFleetStatus(ctx, &pb.GetFleetStatusRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	s := resp.GetStatus()
	fmt.Printf("Fleet: %d hosts, %.0f%% utilization\n", s.GetTotalHosts(), s.GetCapacityUtilizationRatio()*100)
	for _, p := range s.GetPools() {
		fmt.Printf("  %-15s %d hosts, %d/%d cage slots\n", p.GetPool(), p.GetHostCount(), p.GetCageSlotsUsed(), p.GetCageSlotsTotal())
	}

	capResp, err := client.GetCapacity(ctx, &pb.GetCapacityRequest{})
	if err == nil {
		fmt.Printf("\nAvailable cage slots: %d\n", capResp.GetAvailableCageSlots())
	}
}
