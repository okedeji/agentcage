package grpc

import (
	"context"
	"strings"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

type configAdapter struct {
	pb.UnimplementedConfigServiceServer
	server *config.Server
}

func (a *configAdapter) ExportConfig(ctx context.Context, _ *pb.ExportConfigRequest) (*pb.ExportConfigResponse, error) {
	cfg := a.server.GetConfig(ctx)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshaling config: %v", err)
	}
	return &pb.ExportConfigResponse{ConfigYaml: data}, nil
}

func (a *configAdapter) GetConfigValue(ctx context.Context, req *pb.GetConfigValueRequest) (*pb.GetConfigValueResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}
	val, err := a.server.GetValue(ctx, req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &pb.GetConfigValueResponse{Value: val}, nil
}

func (a *configAdapter) SetConfigValue(ctx context.Context, req *pb.SetConfigValueRequest) (*pb.SetConfigValueResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}
	if err := a.server.UpdateValue(ctx, req.GetPath(), req.GetValue()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	restart := isInfrastructurePath(req.GetPath())
	return &pb.SetConfigValueResponse{RestartRequired: restart}, nil
}

func (a *configAdapter) ImportConfig(ctx context.Context, req *pb.ImportConfigRequest) (*pb.ImportConfigResponse, error) {
	if len(req.GetConfigYaml()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "config_yaml is required")
	}
	parsed, err := config.Parse(req.GetConfigYaml())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid config YAML: %v", err)
	}
	a.server.Import(ctx, parsed)
	return &pb.ImportConfigResponse{RestartRequired: true}, nil
}

func (a *configAdapter) CreateAPIKey(ctx context.Context, req *pb.CreateAPIKeyRequest) (*pb.CreateAPIKeyResponse, error) {
	if req.GetName() == "" || req.GetKeyHash() == "" {
		return nil, status.Error(codes.InvalidArgument, "name and key_hash are required")
	}
	entry := config.APIKeyEntry{
		Name:    req.GetName(),
		KeyHash: req.GetKeyHash(),
	}
	if err := a.server.AddAPIKey(ctx, entry); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "%v", err)
	}
	return &pb.CreateAPIKeyResponse{}, nil
}

func (a *configAdapter) ListAPIKeys(ctx context.Context, _ *pb.ListAPIKeysRequest) (*pb.ListAPIKeysResponse, error) {
	cfg := a.server.GetConfig(ctx)
	var keys []*pb.APIKeyInfo
	for _, k := range cfg.Access.APIKeys {
		prefix := k.KeyHash
		if len(prefix) > 20 {
			prefix = prefix[:20] + "..."
		}
		keys = append(keys, &pb.APIKeyInfo{
			Name:          k.Name,
			KeyHashPrefix: prefix,
		})
	}
	return &pb.ListAPIKeysResponse{Keys: keys}, nil
}

func (a *configAdapter) RevokeAPIKey(ctx context.Context, req *pb.RevokeAPIKeyRequest) (*pb.RevokeAPIKeyResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := a.server.RemoveAPIKey(ctx, req.GetName()); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &pb.RevokeAPIKeyResponse{}, nil
}

func isInfrastructurePath(path string) bool {
	for _, prefix := range []string{
		"infrastructure.",
		"grpc.",
		"posture",
		"cage_runtime.",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
