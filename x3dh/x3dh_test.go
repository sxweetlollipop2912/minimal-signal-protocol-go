package x3dh

import (
	"errors"
	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/crypto/signer_schnorr"
	"testing"
)

type BobKeys struct {
	IdentityPrivateKey key_ed25519.PrivateKey
	PrekeyPrivateKey   key_ed25519.PrivateKey
	OneTimePrivateKey  key_ed25519.PrivateKey
}

// generateBobKeys generates the required keys for Bob and returns both the public keys (for the bundle) and the private keys.
func generateBobKeys(withOneTimePrekey bool) (*BobPrekeyBundle, *BobKeys, error) {
	identityKey, err := key_ed25519.New()
	if err != nil {
		return nil, nil, err
	}

	identityPubKey, err := identityKey.Public()
	if err != nil {
		return nil, nil, err
	}

	prekey, err := key_ed25519.New()
	if err != nil {
		return nil, nil, err
	}

	prekeyPubKey, err := prekey.Public()
	if err != nil {
		return nil, nil, err
	}

	// Sign the prekey using Bob's identity key
	prekeySig, err := signer_schnorr.Sign(identityKey, prekeyPubKey)
	if err != nil {
		return nil, nil, err
	}

	bobKeys := &BobKeys{
		IdentityPrivateKey: identityKey,
		PrekeyPrivateKey:   prekey,
	}

	bobBundle := &BobPrekeyBundle{
		IdentityKey: identityPubKey,
		Prekey:      prekeyPubKey,
		PrekeySig:   prekeySig,
	}

	if withOneTimePrekey {
		oneTimePrekey, err := key_ed25519.New()
		if err != nil {
			return nil, nil, err
		}

		oneTimePrekeyPubKey, err := oneTimePrekey.Public()
		if err != nil {
			return nil, nil, err
		}

		bobKeys.OneTimePrivateKey = oneTimePrekey
		bobBundle.OneTimePrekey = oneTimePrekeyPubKey
	}

	return bobBundle, bobKeys, nil
}

func TestPerformKeyAgreement(t *testing.T) {
	// Define test cases
	tests := []struct {
		name              string
		withOneTimePrekey bool
		expectedError     error
	}{
		{
			name:              "Normal case with Bob's one-time prekey",
			withOneTimePrekey: true,
			expectedError:     nil,
		},
		{
			name:              "Case without Bob's one-time prekey",
			withOneTimePrekey: false,
			expectedError:     nil,
		},
		{
			name:              "Verification failure",
			withOneTimePrekey: false,
			expectedError:     errors.New("schnorr: signature of invalid length 17 instead of 64"),
		},
		{
			name:              "Error in ephemeral key generation",
			withOneTimePrekey: false,
			expectedError:     errors.New("wrong size buffer"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate Bob's keys and bundle
			bobBundle, bobKeys, err := generateBobKeys(tt.withOneTimePrekey)
			if err != nil {
				t.Fatalf("error generating Bob's keys: %v", err)
			}

			// Generate Alice's identity key
			aliceIdKey := generatePrivateKey()

			if tt.name == "Verification failure" {
				// Modify the signature to be invalid
				bobBundle.PrekeySig = invalidSignature()
			} else if tt.name == "Error in ephemeral key generation" {
				// Invalidate Alice's identity key to simulate an error during ephemeral key generation
				aliceIdKey = generateInvalidPrivateKey()
			}

			// Perform key agreement
			key, ephPubKey, err := PerformKeyAgreement(bobBundle, aliceIdKey)

			// Check for expected errors
			if err != nil && tt.expectedError == nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tt.expectedError != nil {
				t.Fatalf("expected error but got none")
			}
			if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Fatalf("expected error: %v, got: %v", tt.expectedError, err)
			}

			// If no error, simulate Bob deriving the same key
			if err == nil {
				if len(key) == 0 {
					t.Fatal("derived key is empty")
				}
				if len(ephPubKey) == 0 {
					t.Fatal("ephemeral public key is empty")
				}

				// Simulate Bob's side key derivation
				alicePubIDKey, _ := aliceIdKey.Public()
				dh1, _ := dh25519.GetSecret(&bobKeys.PrekeyPrivateKey, &alicePubIDKey)
				dh2, _ := dh25519.GetSecret(&bobKeys.IdentityPrivateKey, &ephPubKey)
				dh3, _ := dh25519.GetSecret(&bobKeys.PrekeyPrivateKey, &ephPubKey)

				var sk []byte
				sk = append(sk, dh1...)
				sk = append(sk, dh2...)
				sk = append(sk, dh3...)

				if tt.withOneTimePrekey {
					dh4, _ := dh25519.GetSecret(&bobKeys.OneTimePrivateKey, &ephPubKey)
					sk = append(sk, dh4...)
				}

				// Derive the key using HKDF
				derivedKey, err := hkdf.NewFromSecret(sk)
				if err != nil {
					t.Fatal("error deriving key using HKDF: ", err)
				}

				// Check that Alice's derived key matches Bob's derived key
				if !equalKeys(key, derivedKey) {
					t.Fatal("Alice's and Bob's derived keys do not match")
				}
			}
		})
	}
}

// Helper functions

func generatePrivateKey() key_ed25519.PrivateKey {
	privKey, _ := key_ed25519.New()
	return privKey
}

func generateInvalidPrivateKey() key_ed25519.PrivateKey {
	return nil // Simulate an error in key generation
}

func invalidSignature() []byte {
	return []byte("invalid-signature")
}

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
