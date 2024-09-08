package hkdf

import (
	"hash"
	"io"
	"minimal-signal/configs"
	"minimal-signal/crypto"

	"golang.org/x/crypto/hkdf"
)

// New32BytesKeyFromSecret derives a new 32-bit key from a secret using HKDF
func New32BytesKeyFromSecret(secret []byte) ([]byte, error) {
	// X25519 requires 32 bytes of 0xFF for cryptographic domain separation.
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xFF
	}

	// Concatenate the padding with the secret
	paddedSecret := append(padding, secret...)

	// Create an HKDF reader using SHA-256 as the hash function
	hkdfReader := hkdf.New(crypto.DefaultHashFunc, paddedSecret, nil, configs.HKDFInfo)

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
