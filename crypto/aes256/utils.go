package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrInvalidKeySize = errors.New("invalid key size")
)

func NewKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func Encrypt(plaintext, associatedData, key []byte) (ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, associatedData)
	// Prepend the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)
	return ciphertext, nil
}

func Decrypt(ciphertext, associatedData, key []byte) (plaintext []byte, err error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

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
