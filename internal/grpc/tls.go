package grpc

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIREServerTLS returns a tls.Config that uses SPIRE-issued X.509 SVIDs
// for server authentication with auto-rotation. The returned config
// authorizes any client presenting a valid SVID from the same trust domain.
func SPIREServerTLS(ctx context.Context, spireSocket string) (*tls.Config, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(spireSocket)))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIRE workload API at %s: %w", spireSocket, err)
	}

	tlsCfg := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	return tlsCfg, nil
}

// SPIREClientTLS returns a tls.Config for a gRPC client that authenticates
// via SPIRE-issued SVIDs.
func SPIREClientTLS(ctx context.Context, spireSocket string) (*tls.Config, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(spireSocket)))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIRE workload API at %s: %w", spireSocket, err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	return tlsCfg, nil
}
