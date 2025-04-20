package x509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"
)

// Certificate represents an X.509 certificate.
type Certificate struct {
	cert *x509.Certificate
	// Store the DER bytes as well, useful for saving
	derBytes []byte
}

// NewCertificate creates a new self-signed X.509 certificate.
func NewCertificate(
	privKey *PrivateKey, // The private key to sign the certificate
	commonName string, // Subject Common Name (e.g., "example.com")
	organization []string, // Subject Organization (e.g., ["My Company"])
	dnsNames []string, // Subject Alternative Names (DNS)
	ipAddresses []net.IP, // Subject Alternative Names (IP)
	validFor time.Duration, // Duration for which the certificate is valid
	isCA bool, // Whether this certificate is a Certificate Authority
) (*Certificate, error) {

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		slog.Error("Failed to generate serial number", "error", err)
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Get the current time
	now := time.Now()

	// Create the certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: organization,
		},
		NotBefore: now,
		NotAfter:  now.Add(validFor),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // Common usages
		BasicConstraintsValid: true,

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	// If it's a CA, set appropriate fields
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Get the public key from the private key
	pubKey := &privKey.Key().PublicKey

	// Create the certificate (self-signed)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey.Key())
	if err != nil {
		slog.Error("Failed to create certificate", "error", err)
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the created certificate to get the *x509.Certificate object
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		slog.Error("Failed to parse created certificate", "error", err)
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	slog.Info("Successfully created new certificate", "subject", commonName, "serial", serialNumber)
	return &Certificate{cert: cert, derBytes: derBytes}, nil
}

// Cert returns the underlying *x509.Certificate.
func (c *Certificate) Cert() *x509.Certificate {
	return c.cert
}

// DERBytes returns the DER-encoded bytes of the certificate.
func (c *Certificate) DERBytes() []byte {
	return c.derBytes
}

// SaveToFile saves the certificate to the specified file path in DER format.
func (c *Certificate) SaveToFile(filePath string) error {
	if c.derBytes == nil {
		return fmt.Errorf("certificate DER bytes are nil, cannot save")
	}
	// Save the DER-encoded certificate to a file
	if err := os.WriteFile(filePath, c.derBytes, 0644); err != nil { // Use 0644 for certificate permissions
		slog.Error("Failed to write DER data to certificate file", "path", filePath, "error", err)
		return fmt.Errorf("failed to write DER data to certificate file %s: %w", filePath, err)
	}
	slog.Info("Saved certificate in DER format", "path", filePath)
	return nil
}
