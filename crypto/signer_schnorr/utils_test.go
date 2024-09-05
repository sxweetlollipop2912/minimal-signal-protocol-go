package signer_schnorr

import (
	"testing"

	"minimal-signal/crypto/key_ed25519"

	"github.com/stretchr/testify/assert"
)

func TestSignAndVerify(t *testing.T) {
	// Generate a key pair
	privKey, err := key_ed25519.New()
	assert.NoError(t, err)
	pubKey, err := privKey.Public()
	assert.NoError(t, err)

	// Define test cases
	tests := []struct {
		name      string
		msg       []byte
		shouldErr bool
	}{
		{"Valid message", []byte("test message"), false},
		{"Empty message", []byte(""), false},
		{"Another valid message", []byte("another test message"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Sign function
			sig, err := Sign(*privKey, tt.msg)
			if tt.shouldErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, sig)

			// Test Verify function
			err = Verify(*pubKey, tt.msg, sig)
			assert.NoError(t, err)

			// Test Verify with a wrong message
			wrongMsg := []byte("wrong message")
			err = Verify(*pubKey, wrongMsg, sig)
			assert.Error(t, err)

			// Test Verify with a wrong signature
			wrongSig, _ := Sign(*privKey, wrongMsg)
			err = Verify(*pubKey, tt.msg, wrongSig)
			assert.Error(t, err)
		})
	}
}
