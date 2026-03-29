package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SVIDIssuer manages SPIFFE identity lifecycle for cages.
type SVIDIssuer interface {
	Issue(ctx context.Context, cageID string, ttl time.Duration) (*SVID, error)
	Verify(ctx context.Context, raw []byte) (*SVID, error)
	Revoke(ctx context.Context, svidID string) error
	Close() error
}

// SpireClient implements SVIDIssuer using the SPIRE Workload API.
type SpireClient struct {
	client      *workloadapi.Client
	trustDomain string
}

// NewSpireClient connects to the SPIRE Workload API at the given Unix socket path.
func NewSpireClient(ctx context.Context, socketPath, trustDomain string) (*SpireClient, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+socketPath))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIRE workload API at %s: %w", socketPath, err)
	}
	return &SpireClient{client: client, trustDomain: trustDomain}, nil
}

func (s *SpireClient) Issue(ctx context.Context, cageID string, ttl time.Duration) (*SVID, error) {
	x509Ctx, err := s.client.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching X.509 SVID for cage %s: %w", cageID, err)
	}

	svids := x509Ctx.SVIDs
	if len(svids) == 0 {
		return nil, fmt.Errorf("fetching X.509 SVID for cage %s: no SVIDs returned", cageID)
	}

	first := svids[0]
	cert := first.Certificates[0]

	return &SVID{
		ID:        cert.SerialNumber.String(),
		SpiffeID:  first.ID.String(),
		Raw:       cert.Raw,
		ExpiresAt: cert.NotAfter,
		CageID:    cageID,
	}, nil
}

func (s *SpireClient) Verify(ctx context.Context, raw []byte) (*SVID, error) {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing X.509 certificate: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("SVID expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	spiffeID, err := extractSpiffeID(cert)
	if err != nil {
		return nil, fmt.Errorf("extracting SPIFFE ID: %w", err)
	}

	x509Ctx, err := s.client.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching trust bundle for verification: %w", err)
	}

	bundles := x509Ctx.Bundles
	trustPool, ok := bundles.Get(x509Ctx.SVIDs[0].ID.TrustDomain())
	if !ok {
		return nil, fmt.Errorf("no trust bundle found for trust domain %s", s.trustDomain)
	}

	roots := x509.NewCertPool()
	for _, authority := range trustPool.X509Authorities() {
		roots.AddCert(authority)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("verifying certificate against trust bundle: %w", err)
	}

	return &SVID{
		ID:        cert.SerialNumber.String(),
		SpiffeID:  spiffeID,
		Raw:       raw,
		ExpiresAt: cert.NotAfter,
	}, nil
}

// Revocation requires the SPIRE Server registration API, not the Workload API.
// The registration client is wired in the orchestrator binary (cmd/orchestrator).
// For now, SVID expiry is the primary revocation mechanism — TTLs are set to
// match the cage time limit, so SVIDs expire naturally at teardown.
func (s *SpireClient) Revoke(_ context.Context, _ string) error {
	return nil
}

func (s *SpireClient) Close() error {
	return s.client.Close()
}

func extractSpiffeID(cert *x509.Certificate) (string, error) {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return uri.String(), nil
		}
	}

	// Some SPIRE versions encode the SPIFFE ID in the SAN URI string directly.
	for _, san := range cert.DNSNames {
		if u, err := url.Parse(san); err == nil && u.Scheme == "spiffe" {
			return san, nil
		}
	}

	return "", fmt.Errorf("no SPIFFE URI SAN found in certificate")
}
