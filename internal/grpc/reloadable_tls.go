package grpc

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// ReloadableCert holds a TLS certificate that can be swapped
// atomically at runtime. The gRPC server's file-TLS path uses this so
// SIGHUP can rotate the operator-PKI cert without a restart. The
// SPIRE-internal TLS branch doesn't need it; the workload API rotates
// SVIDs automatically.
//
// Concurrency: Reload may run from any goroutine. The atomic pointer
// ensures GetCertificate (called by the TLS handshake on every new
// connection) always sees a consistent cert, even mid-reload.
type ReloadableCert struct {
	certFile string
	keyFile  string
	current  atomic.Pointer[tls.Certificate]
}

// NewReloadableCert loads cert+key from disk and returns a holder
// ready to install via TLSConfig().
func NewReloadableCert(certFile, keyFile string) (*ReloadableCert, error) {
	r := &ReloadableCert{certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads cert+key from disk and swaps them in atomically.
// New connections after Reload returns use the new cert. In-flight
// handshakes that already called GetCertificate keep the old one.
func (r *ReloadableCert) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS keypair from %s/%s: %w", r.certFile, r.keyFile, err)
	}
	r.current.Store(&cert)
	return nil
}

// TLSConfig returns a *tls.Config wired to this holder via
// GetCertificate. The returned config has no static Certificates
// slice; every handshake pulls the current cert through
// GetCertificate, picking up reloads.
func (r *ReloadableCert) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: PreferredCipherSuites,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := r.current.Load()
			if c == nil {
				return nil, fmt.Errorf("reloadable cert: no certificate loaded")
			}
			return c, nil
		},
	}
}
