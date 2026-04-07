package grpc

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RecoveryUnaryInterceptor turns panics in handlers into gRPC INTERNAL errors
// instead of crashing the orchestrator process. The full stack is logged so
// the operator can diagnose; the client gets a generic message so internals
// don't leak across the trust boundary.
func RecoveryUnaryInterceptor(log logr.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error(nil, "panic in grpc handler",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// LoggingUnaryInterceptor records every call's method, peer, duration, and
// gRPC status code. Errors are logged at error level; successful calls at
// V(1) so debug-level logging shows them but Info-level does not.
func LoggingUnaryInterceptor(log logr.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		peerAddr := "unknown"
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			peerAddr = p.Addr.String()
		}

		code := status.Code(err)
		if err != nil {
			log.Error(err, "grpc call failed",
				"method", info.FullMethod,
				"peer", peerAddr,
				"duration_ms", duration.Milliseconds(),
				"code", code.String(),
			)
		} else {
			log.V(1).Info("grpc call",
				"method", info.FullMethod,
				"peer", peerAddr,
				"duration_ms", duration.Milliseconds(),
				"code", code.String(),
			)
		}
		return resp, err
	}
}
