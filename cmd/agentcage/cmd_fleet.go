package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
)

func cmdFleet(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "hosts":
			cmdFleetHosts(args[1:])
			return
		case "drain":
			cmdFleetDrain(args[1:])
			return
		}
	}

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewFleetServiceClient(conn)

	statusResp, err := client.GetFleetStatus(ctx, &pb.GetFleetStatusRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	s := statusResp.GetStatus()
	fmt.Printf("Fleet: %d hosts, %.0f%% utilization\n\n", s.GetTotalHosts(), s.GetCapacityUtilizationRatio()*100)
	for _, p := range s.GetPools() {
		fmt.Printf("  %-15s %d hosts, %d/%d cage slots\n", p.GetPool(), p.GetHostCount(), p.GetCageSlotsUsed(), p.GetCageSlotsTotal())
	}

	capResp, err := client.GetCapacity(ctx, &pb.GetCapacityRequest{})
	if err == nil {
		fmt.Printf("\nAvailable cage slots: %d\n", capResp.GetAvailableCageSlots())
	}
}

func cmdFleetHosts(args []string) {
	fs := flag.NewFlagSet("fleet hosts", flag.ExitOnError)
	pool := fs.String("pool", "", "filter by pool: active, warm, provisioning, draining")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewFleetServiceClient(conn)

	req := &pb.ListHostsRequest{}
	if *pool != "" {
		p, ok := parsePoolFilter(*pool)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown pool %q (valid: active, warm, provisioning, draining)\n", *pool)
			os.Exit(1)
		}
		req.PoolFilter = p
	}

	resp, err := client.ListHosts(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	hosts := resp.GetHosts()
	if len(hosts) == 0 {
		fmt.Println("No hosts.")
		return
	}

	for _, h := range hosts {
		fmt.Printf("  %-20s  %-13s  %-12s  slots %d/%d  cpu %d/%d  mem %d/%d MB\n",
			h.GetHostId(),
			h.GetPool(),
			h.GetState(),
			h.GetCageSlotsUsed(), h.GetCageSlotsTotal(),
			h.GetVcpusUsed(), h.GetVcpusTotal(),
			h.GetMemoryMbUsed(), h.GetMemoryMbTotal(),
		)
	}
}

func cmdFleetDrain(args []string) {
	fs := flag.NewFlagSet("fleet drain", flag.ExitOnError)
	hostID := fs.String("host", "", "host ID to drain (required)")
	reason := fs.String("reason", "", "reason for draining")
	force := fs.Bool("force", false, "force drain pinned hosts")
	_ = fs.Parse(args)

	if *hostID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage fleet drain --host <id> --reason <reason> [--force]")
		os.Exit(1)
	}

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewFleetServiceClient(conn)
	if _, err := client.DrainHost(ctx, &pb.DrainHostRequest{
		HostId: *hostID,
		Reason: *reason,
		Force:  *force,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Host %s draining.\n", *hostID)
}

func parsePoolFilter(s string) (pb.HostPool, bool) {
	switch s {
	case "active":
		return pb.HostPool_HOST_POOL_ACTIVE, true
	case "warm":
		return pb.HostPool_HOST_POOL_WARM, true
	case "provisioning":
		return pb.HostPool_HOST_POOL_PROVISIONING, true
	case "draining":
		return pb.HostPool_HOST_POOL_DRAINING, true
	default:
		return pb.HostPool_HOST_POOL_UNSPECIFIED, false
	}
}
