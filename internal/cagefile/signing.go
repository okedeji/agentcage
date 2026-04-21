package cagefile

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrGenerateSigningKey reads an Ed25519 private key from path,
// or generates one and writes it if the file does not exist. The
// key is stored as a PKCS8-encoded PEM.
func LoadOrGenerateSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePrivateKeyPEM(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading signing key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling signing key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("writing signing key %s: %w", path, err)
	}

	return priv, nil
}

// LoadPublicKeyFile reads an Ed25519 public key from a PEM file.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", path, err)
	}
	return ParsePublicKeyPEM(data)
}

// ParsePublicKeyPEM parses an Ed25519 public key from PEM bytes.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edPub, nil
}

// ExportPublicKeyPEM returns the PEM-encoded public key for a private key.
func ExportPublicKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), nil
}

func parsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}
