package grpc

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type vaultAdapter struct {
	pb.UnimplementedVaultServiceServer
	reader identity.SecretReader
}

func (a *vaultAdapter) PutSecret(ctx context.Context, req *pb.PutSecretRequest) (*pb.PutSecretResponse, error) {
	path, err := vaultPath(req.GetScope(), req.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(req.GetValue(), &data); err != nil {
		data = map[string]any{"value": string(req.GetValue())}
	}

	if err := a.reader.WriteSecret(ctx, path, data); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.PutSecretResponse{}, nil
}

func (a *vaultAdapter) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	path, err := vaultPath(req.GetScope(), req.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	data, err := a.reader.ReadSecret(ctx, path)
	if err != nil {
		return nil, toGRPCError(err)
	}

	raw, _ := json.Marshal(data)
	return &pb.GetSecretResponse{Value: raw}, nil
}

func (a *vaultAdapter) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	prefix, err := vaultPrefix(req.GetScope())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	keys, err := a.reader.ListSecrets(ctx, prefix)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.ListSecretsResponse{Keys: keys}, nil
}

func (a *vaultAdapter) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	path, err := vaultPath(req.GetScope(), req.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	if err := a.reader.DeleteSecret(ctx, path); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.DeleteSecretResponse{}, nil
}

func vaultPath(scope, key string) (string, error) {
	prefix, err := vaultPrefix(scope)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", fmt.Errorf("key is required")
	}
	return prefix + key, nil
}

func vaultPrefix(scope string) (string, error) {
	switch scope {
	case "orchestrator":
		return "secret/data/agentcage/orchestrator/", nil
	case "target":
		return "secret/data/agentcage/target/", nil
	default:
		return "", fmt.Errorf("scope must be 'orchestrator' or 'target', got %q", scope)
	}
}
