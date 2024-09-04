package alice

import (
	"errors"
	"testing"

	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/crypto/signer_schnorr"

	"github.com/stretchr/testify/assert"
)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate Bob's keys and bundle
			bobBundle, bobKeys, err := generateBobKeys(tt.withOneTimePrekey)
			assert.NoError(t, err, "error generating Bob's keys")

			// Generate Alice's identity key
			aliceIdKey := generatePrivateKey()

			if tt.name == "Verification failure" {
				// Modify the signature to be invalid
				bobBundle.PrekeySig = invalidSignature()
			}

			// Perform key agreement
			key, ephPubKey, err := PerformKeyAgreement(bobBundle, aliceIdKey)

			// Check for expected errors
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError.Error())
				assert.Nil(t, key, "derived key is not nil")
			} else {
				assert.NoError(t, err)

				// If no error, simulate Bob deriving the same key
				assert.NotEmpty(t, key, "derived key is empty")
				assert.NotEmpty(t, ephPubKey, "ephemeral public key is empty")

				// Simulate Bob's side key derivation
				alicePubIDKey, _ := aliceIdKey.Public()
				dh1, _ := dh25519.GetSecret(bobKeys.PrekeyPrivateKey, *alicePubIDKey)
				dh2, _ := dh25519.GetSecret(bobKeys.IdentityPrivateKey, *ephPubKey)
				dh3, _ := dh25519.GetSecret(bobKeys.PrekeyPrivateKey, *ephPubKey)

				var sk []byte
				sk = append(sk, dh1...)
				sk = append(sk, dh2...)
				sk = append(sk, dh3...)

				if tt.withOneTimePrekey {
					dh4, _ := dh25519.GetSecret(bobKeys.OneTimePrivateKey, *ephPubKey)
					sk = append(sk, dh4...)
				}

				// Derive the key using HKDF
				derivedKey, err := hkdf.New32BytesKeyFromSecret(sk)
				assert.NoError(t, err, "error deriving key using HKDF")

				// Check that Alice's derived key matches Bob's derived key
				assert.True(t, equalKeys(key, derivedKey), "Alice's and Bob's derived keys do not match")
			}
		})
	}
}

// Helper functions

type BobPrivKeys struct {
	IdentityPrivateKey key_ed25519.PrivateKey
	PrekeyPrivateKey   key_ed25519.PrivateKey
	OneTimePrivateKey  key_ed25519.PrivateKey
}

// generateBobKeys generates the required keys for Bob and returns both the public keys (for the bundle) and the private keys.
func generateBobKeys(withOneTimePrekey bool) (*BobPrekeyBundle, *BobPrivKeys, error) {
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
	prekeyPubKeyBytes := [32]byte(*prekeyPubKey)
	prekeySig, err := signer_schnorr.Sign(*identityKey, prekeyPubKeyBytes[:])
	if err != nil {
		return nil, nil, err
	}

	bobKeys := &BobPrivKeys{
		IdentityPrivateKey: *identityKey,
		PrekeyPrivateKey:   *prekey,
	}

	bobBundle := &BobPrekeyBundle{
		IdentityKey: *identityPubKey,
		Prekey:      *prekeyPubKey,
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

		bobKeys.OneTimePrivateKey = *oneTimePrekey
		bobBundle.OneTimePrekey = oneTimePrekeyPubKey
	}

	return bobBundle, bobKeys, nil
}

func generatePrivateKey() key_ed25519.PrivateKey {
	privKey, _ := key_ed25519.New()
	return *privKey
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
