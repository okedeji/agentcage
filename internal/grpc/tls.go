package grpc

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// PreferredCipherSuites locks file-based TLS to AEAD ciphers with
// forward secrecy. SPIRE-managed configs don't use this; go-spiffe
// controls its own cipher selection.
var PreferredCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// SPIREServerTLS returns a tls.Config that uses SPIRE-issued X.509 SVIDs
// for server authentication with auto-rotation. Only clients presenting a
// valid SVID from the specified trust domain are accepted.
func SPIREServerTLS(ctx context.Context, spireSocket string, trustDomain spiffeid.TrustDomain) (*tls.Config, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(spireSocket)))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIRE workload API at %s: %w", spireSocket, err)
	}

	tlsCfg := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(trustDomain))
	return tlsCfg, nil
}

// SPIREClientTLS returns a tls.Config for a gRPC client that authenticates
// via SPIRE-issued SVIDs. Only servers presenting a valid SVID from the
// specified trust domain are accepted.
func SPIREClientTLS(ctx context.Context, spireSocket string, trustDomain spiffeid.TrustDomain) (*tls.Config, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(spireSocket)))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIRE workload API at %s: %w", spireSocket, err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(trustDomain))
	return tlsCfg, nil
}
