package main

import (
	"context"

	pb "github.com/okedeji/agentcage/api/proto"
)

// controlServer implements the ControlService gRPC for VM-based shutdown and health checks.
type controlServer struct {
	pb.UnimplementedControlServiceServer
	cancelFunc context.CancelFunc
}

func newControlServer(cancel context.CancelFunc) *controlServer {
	return &controlServer{cancelFunc: cancel}
}

func (s *controlServer) Ping(_ context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		Version: version,
		Status:  "running",
	}, nil
}

func (s *controlServer) Stop(_ context.Context, _ *pb.StopRequest) (*pb.StopResponse, error) {
	s.cancelFunc()
	return &pb.StopResponse{}, nil
}

func (s *controlServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Services: map[string]string{
			"status": "ok",
		},
	}, nil
}
