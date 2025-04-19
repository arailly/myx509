package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
)

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	key *ecdsa.PrivateKey
}

// NewPrivateKey generates a new ECDSA private key.
func NewPrivateKey() (*PrivateKey, error) {
	// Generate a new ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		// Use slog for error logging
		slog.Error("Failed to generate private key", "error", err)
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	// Use slog for info logging
	slog.Info("Generated new private key")
	return &PrivateKey{key: priv}, nil
}

// Key returns the underlying *ecdsa.PrivateKey.
func (p *PrivateKey) Key() *ecdsa.PrivateKey {
	return p.key
}

// SaveToFile saves the private key to the specified file path in DER format.
func (p *PrivateKey) SaveToFile(filePath string) error {
	// Marshal the private key to DER format
	der, err := x509.MarshalECPrivateKey(p.key)
	if err != nil {
		// Use slog for error logging
		slog.Error("Failed to marshal private key to DER", "error", err)
		return fmt.Errorf("failed to marshal private key to DER: %w", err)
	}

	// Save the DER-encoded private key to a file
	if err := os.WriteFile(filePath, der, 0600); err != nil { // Use 0600 for private key permissions
		// Use slog for error logging
		slog.Error("Failed to write DER data to private key file", "path", filePath, "error", err)
		return fmt.Errorf("failed to write DER data to private key file %s: %w", filePath, err)
	}
	// Use slog for info logging
	slog.Info("Saved private key in DER format", "path", filePath)
	return nil
}

// LoadPrivateKeyFromFile loads an existing private key from a DER-encoded file.
func LoadPrivateKeyFromFile(filePath string) (*PrivateKey, error) {
	// Read the DER-encoded private key file
	derData, err := os.ReadFile(filePath)
	if err != nil {
		// Use slog for error logging
		slog.Error("Failed to read private key file", "path", filePath, "error", err)
		return nil, fmt.Errorf("failed to read private key file %s: %w", filePath, err)
	}

	// Parse the DER-encoded private key
	privKey, err := x509.ParseECPrivateKey(derData)
	if err != nil {
		// Use slog for error logging
		slog.Error("Failed to parse DER-encoded private key", "path", filePath, "error", err)
		return nil, fmt.Errorf("failed to parse DER-encoded private key from %s: %w", filePath, err)
	}
	// Use slog for info logging
	slog.Info("Loaded private key in DER format", "path", filePath)
	return &PrivateKey{key: privKey}, nil
}
