package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// AuthIdentity is attached to the context after successful authentication.
type AuthIdentity struct {
	Name   string
	Method string // "mtls" or "api_key"
}

type authContextKey struct{}

// IdentityFromContext returns the authenticated identity, if any.
func IdentityFromContext(ctx context.Context) *AuthIdentity {
	if v, ok := ctx.Value(authContextKey{}).(*AuthIdentity); ok {
		return v
	}
	return nil
}

// AuthUnaryInterceptor checks every gRPC call for a valid client
// certificate (mTLS) or API key (Bearer token in metadata). API keys
// are read from cfgServer on each request so newly created keys work
// immediately without a restart.
func AuthUnaryInterceptor(cfgServer *config.Server, requireMTLS bool, log logr.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		cfg := cfgServer.GetConfig(ctx)
		noAuth := !requireMTLS && len(cfg.Access.APIKeys) == 0

		if noAuth {
			return handler(ctx, req)
		}

		// Skip auth for health/ping — needed for connect to work
		// before the client has credentials.
		if strings.HasSuffix(info.FullMethod, "/Ping") || strings.HasSuffix(info.FullMethod, "/Health") {
			return handler(ctx, req)
		}

		// Try mTLS first.
		if p, ok := peer.FromContext(ctx); ok && p.AuthInfo != nil {
			if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				if len(tlsInfo.State.VerifiedChains) > 0 && len(tlsInfo.State.VerifiedChains[0]) > 0 {
					cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
					if cn != "" {
						identity := &AuthIdentity{Name: cn, Method: "mtls"}
						log.V(1).Info("authenticated via mTLS", "cn", cn, "method", info.FullMethod)
						ctx = context.WithValue(ctx, authContextKey{}, identity)
						return handler(ctx, req)
					}
				}
			}
		}

		// Try API key from metadata.
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if vals := md.Get("authorization"); len(vals) > 0 {
				token := strings.TrimPrefix(vals[0], "Bearer ")
				token = strings.TrimSpace(token)
				if token != "" {
					hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(token)))
					for _, k := range cfg.Access.APIKeys {
						if subtle.ConstantTimeCompare([]byte(hash), []byte(k.KeyHash)) == 1 {
							identity := &AuthIdentity{Name: k.Name, Method: "api_key"}
							log.V(1).Info("authenticated via API key", "name", k.Name, "method", info.FullMethod)
							ctx = context.WithValue(ctx, authContextKey{}, identity)
							return handler(ctx, req)
						}
					}
					return nil, status.Error(codes.Unauthenticated, "invalid API key")
				}
			}
		}

		if requireMTLS {
			return nil, status.Error(codes.Unauthenticated, "client certificate required")
		}
		return nil, status.Error(codes.Unauthenticated, "authentication required (mTLS or API key)")
	}
}

// HashAPIKey returns the sha256 hash of an API key in the format stored in config.
func HashAPIKey(key string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(key)))
}

// CompareKeyHash compares a plaintext key against a stored hash.
func CompareKeyHash(key, storedHash string) bool {
	computed := HashAPIKey(key)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}
