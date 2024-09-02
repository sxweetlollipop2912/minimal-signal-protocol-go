package hkdf

import (
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"minimal-signal/crypto"
)

// New32BytesKeyFromSecret derives a new 32-bit key from a secret using HKDF
func New32BytesKeyFromSecret(secret []byte) ([]byte, error) {
	// Create an HKDF reader using SHA-256 as the hash function
	hkdfReader := hkdf.New(crypto.DefaultHashFunc, secret, nil, nil)

	// Create a buffer to hold the derived key
	key := make([]byte, 32)

	// Read the derived key from the HKDF reader
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// KDF to help with the ratchet
func KDF(hash func() hash.Hash, keyMaterial []byte, salt []byte, info []byte, buffer []byte) (int, error) {
	hkdfReader := hkdf.New(hash, keyMaterial[:], salt[:], info)
	return io.ReadFull(hkdfReader, buffer)
}
