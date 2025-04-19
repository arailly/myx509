package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/arailly/myx509/x509"
)

func main() {
	// Specify the output file name via command-line argument
	var outputFilePath string
	flag.StringVar(&outputFilePath, "o", "private_key.der", "Output file path for the private key (DER format)")
	flag.Parse()

	if outputFilePath == "" {
		slog.Error("Output file path cannot be empty")
		flag.Usage() // Show help message
		os.Exit(1)
	}

	// Generate a new private key
	privKey, err := x509.NewPrivateKey()
	if err != nil {
		slog.Error("Failed to generate private key", "error", err)
		os.Exit(1)
	}

	// Save the private key to a file
	if err := privKey.SaveToFile(outputFilePath); err != nil {
		slog.Error("Failed to save private key to file", "path", outputFilePath, "error", err)
		os.Exit(1)
	}

	slog.Info("Successfully generated and saved private key", "path", outputFilePath)
}
