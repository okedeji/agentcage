package grpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidityYears     = 10
	serverValidityYears = 2
)

// TLSCerts holds paths to generated TLS certificate files.
type TLSCerts struct {
	CAFile     string
	CertFile   string
	KeyFile    string
}

// EnsureTLSCerts generates a self-signed CA and server certificate if
// they don't already exist. Returns the paths to the cert files.
// The CA is valid for 10 years, the server cert for 2 years.
func EnsureTLSCerts(tlsDir, hostname string) (*TLSCerts, error) {
	caKeyPath := filepath.Join(tlsDir, "ca.key")
	caCertPath := filepath.Join(tlsDir, "ca.pem")
	serverKeyPath := filepath.Join(tlsDir, "server.key")
	serverCertPath := filepath.Join(tlsDir, "server.crt")

	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return nil, fmt.Errorf("creating TLS directory %s: %w", tlsDir, err)
	}

	// Generate CA if missing.
	if !fileExists(caCertPath) || !fileExists(caKeyPath) {
		if err := generateCA(caKeyPath, caCertPath); err != nil {
			return nil, fmt.Errorf("generating CA: %w", err)
		}
	}

	// Generate server cert if missing.
	if !fileExists(serverCertPath) || !fileExists(serverKeyPath) {
		if err := generateServerCert(caKeyPath, caCertPath, serverKeyPath, serverCertPath, hostname); err != nil {
			return nil, fmt.Errorf("generating server cert: %w", err)
		}
	}

	return &TLSCerts{
		CAFile:   caCertPath,
		CertFile: serverCertPath,
		KeyFile:  serverKeyPath,
	}, nil
}

// LoadServerTLS loads the generated server cert and returns a tls.Config
// for the gRPC server.
func LoadServerTLS(certs *TLSCerts) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certs.CertFile, certs.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ReadCACert reads the CA certificate PEM bytes for distribution to clients.
func ReadCACert(certs *TLSCerts) ([]byte, error) {
	return os.ReadFile(certs.CAFile)
}

func generateCA(keyPath, certPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"agentcage"},
			CommonName:   "agentcage CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if err := writeKeyPEM(keyPath, key); err != nil {
		return err
	}
	return writeCertPEM(certPath, certDER)
}

func generateServerCert(caKeyPath, caCertPath, serverKeyPath, serverCertPath, hostname string) error {
	caKey, err := loadECKey(caKeyPath)
	if err != nil {
		return fmt.Errorf("loading CA key: %w", err)
	}
	caCert, err := loadCert(caCertPath)
	if err != nil {
		return fmt.Errorf("loading CA cert: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"agentcage"},
			CommonName:   hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(serverValidityYears, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Add the hostname as both DNS name and IP (if it's an IP).
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	// Always include localhost for local dev.
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	if err := writeKeyPEM(serverKeyPath, serverKey); err != nil {
		return err
	}
	return writeCertPEM(serverCertPath, certDER)
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600)
}

func writeCertPEM(path string, certDER []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
}

func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
