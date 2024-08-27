package hkdf

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

// NewFromSecret derives a new 32-bit key from a secret using HKDF
func NewFromSecret(secret []byte) ([]byte, error) {
	// Create an HKDF reader using SHA-256 as the hash function
	hkdfReader := hkdf.New(sha256.New, secret, nil, nil)

	// Create a buffer to hold the derived key
	key := make([]byte, 32)

	// Read the derived key from the HKDF reader
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}
