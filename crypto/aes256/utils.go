package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var (
	ErrCiphertextLengthInvalid = errors.New("ciphertext length invalid")
)

// Encrypt encrypts the plaintext using AES-256 in CBC mode with PKCS#7 padding.
func Encrypt(plaintext []byte, key [32]byte, iv [16]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	paddedPlaintext := pkcs7Padding(plaintext[:], block.BlockSize())
	ciphertext = make([]byte, len(paddedPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(ciphertext, paddedPlaintext)
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext using AES-256 in CBC mode with PKCS#7 padding.
func Decrypt(ciphertext []byte, key [32]byte, iv [16]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, ErrCiphertextLengthInvalid
	}

	mode := cipher.NewCBCDecrypter(block, iv[:])
	plaintext = make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext[:])

	return pkcs7Unpadding(plaintext), nil
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
