package main

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arailly/myx509/x509"
)

func main() {
	// Specify the output file name for the private key via command-line argument
	var privKeyFilePath string
	flag.StringVar(&privKeyFilePath, "key", "private_key.der", "Output file path for the private key (DER format)")

	// Specify the output file name for the certificate via command-line argument
	var certFilePath string
	flag.StringVar(&certFilePath, "cert", "", "Output file path for the certificate (DER format). Defaults to <key_name>.crt")

	// Certificate details from command line arguments
	var commonName string
	flag.StringVar(&commonName, "cn", "Self Signed Cert", "Subject Common Name for the certificate")
	var org string
	flag.StringVar(&org, "org", "My Org", "Subject Organization for the certificate")
	var validityDays int
	flag.IntVar(&validityDays, "days", 365, "Validity duration for the certificate in days")

	flag.Parse()

	if privKeyFilePath == "" {
		slog.Error("Private key output file path cannot be empty")
		flag.Usage() // Show help message
		os.Exit(1)
	}

	// If cert path is not specified, derive it from the key path
	if certFilePath == "" {
		baseName := strings.TrimSuffix(privKeyFilePath, filepath.Ext(privKeyFilePath))
		certFilePath = baseName + ".crt"
	}

	// --- Generate Private Key ---
	slog.Info("Generating new private key...")
	privKey, err := x509.NewPrivateKey()
	if err != nil {
		slog.Error("Failed to generate private key", "error", err)
		os.Exit(1)
	}

	// --- Save Private Key ---
	slog.Info("Saving private key...", "path", privKeyFilePath)
	if err := privKey.SaveToFile(privKeyFilePath); err != nil {
		slog.Error("Failed to save private key to file", "path", privKeyFilePath, "error", err)
		os.Exit(1)
	}
	slog.Info("Successfully saved private key", "path", privKeyFilePath)

	// --- Generate Certificate ---
	slog.Info("Generating new certificate...")
	validFor := time.Duration(validityDays) * 24 * time.Hour
	cert, err := x509.NewCertificate(
		privKey,
		commonName,
		[]string{org},
		[]string{}, // No DNS names for now
		[]net.IP{}, // No IP addresses for now
		validFor,
		false, // Not a CA
	)
	if err != nil {
		slog.Error("Failed to generate certificate", "error", err)
		os.Exit(1)
	}

	// --- Save Certificate ---
	slog.Info("Saving certificate...", "path", certFilePath)
	if err := cert.SaveToFile(certFilePath); err != nil {
		slog.Error("Failed to save certificate to file", "path", certFilePath, "error", err)
		os.Exit(1)
	}
	slog.Info("Successfully generated and saved certificate", "path", certFilePath)
}
