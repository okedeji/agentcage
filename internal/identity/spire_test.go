package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCert(t *testing.T, spiffeID string, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		require.NoError(t, err)
		template.URIs = []*url.URL{u}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return der
}

func TestExtractSpiffeID_Valid(t *testing.T) {
	raw := generateTestCert(t,
		"spiffe://example.org/cage/test-cage-1",
		time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour),
	)

	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)

	id, err := extractSpiffeID(cert)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/cage/test-cage-1", id)
}

func TestExtractSpiffeID_Missing(t *testing.T) {
	raw := generateTestCert(t, "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)

	_, err = extractSpiffeID(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SPIFFE URI SAN")
}

func TestVerify_ExpiredCert(t *testing.T) {
	raw := generateTestCert(t,
		"spiffe://example.org/cage/expired",
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-time.Hour),
	)

	s := &SpireClient{trustDomain: "example.org"}
	_, err := s.Verify(t.Context(), raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerify_MalformedBytes(t *testing.T) {
	s := &SpireClient{trustDomain: "example.org"}
	_, err := s.Verify(t.Context(), []byte("not a certificate"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing X.509 certificate")
}

func TestRevoke_ReturnsNil(t *testing.T) {
	s := &SpireClient{trustDomain: "example.org"}
	err := s.Revoke(t.Context(), "some-svid-id")
	assert.NoError(t, err)
}
