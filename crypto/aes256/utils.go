package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func NewKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts the plaintext using AES-256 in CBC mode with PKCS#7 padding.
func Encrypt(plaintext, associatedData, encKey [32]byte, iv [16]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}

	paddedPlaintext := pkcs7Padding(plaintext[:], block.BlockSize())

	mode := cipher.NewCBCEncrypter(block, iv[:])

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, associatedData)
	// Prepend the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext using AES-256 in CBC mode with PKCS#7 padding.
func Decrypt(ciphertext, associatedData, encKey [32]byte, iv [16]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	// Extract the nonce from the beginning of the ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err = aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Helper function for PKCS#7 padding
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Helper function for PKCS#7 unpadding
func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
