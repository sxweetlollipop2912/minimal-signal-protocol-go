package main

import (
	"fmt"
	"log"

	"minimal-signal/crypto/key_ed25519"
)

func main() {
	// Generate a new private key
	privateKey, err := key_ed25519.New()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Derive the public key from the private key
	publicKey, err := privateKey.Public()
	if err != nil {
		log.Fatalf("Failed to derive public key: %v", err)
	}

	// Print the private and public key in hex format
	fmt.Printf("PRIVATE: %x\n", *privateKey)
	fmt.Printf("PUBLIC: %x\n", *publicKey)
}
