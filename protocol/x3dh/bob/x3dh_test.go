package bob

import (
	"testing"

	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/key_ed25519"

	"github.com/stretchr/testify/assert"
)

func TestPerformKeyAgreement(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate Bob's keys and bundle
			bobBundle, bobKeys, err := generateBobKeys(tt.withOneTimePrekey)
			assert.NoError(t, err, "error generating Bob's keys")

			// Generate Alice's keys and bundle
			aliceBundle, aliceIdentityPrivateKey, aliceEphemeralPrivateKey, err := generateAliceKeys()
			assert.NoError(t, err, "error generating Alice's keys")

			// Perform key agreement on Bob's side
			key, err := PerformKeyAgreement(bobBundle, aliceBundle)

			// Check for expected errors
			assert.NoError(t, err, "unexpected error during Bob's key agreement")

			// Verify that the derived key is not empty
			assert.NotEmpty(t, key, "derived key is empty")

			// Simulate Alice deriving the same key by performing the Diffie-Hellman operations
			dh1, _ := dh25519.GetSharedSecret(aliceIdentityPrivateKey, bobKeys.PrekeyPublicKey)
			dh2, _ := dh25519.GetSharedSecret(aliceEphemeralPrivateKey, bobKeys.IdentityPublicKey)
			dh3, _ := dh25519.GetSharedSecret(aliceEphemeralPrivateKey, bobKeys.PrekeyPublicKey)

			var sk []byte
			sk = append(sk, dh1...)
			sk = append(sk, dh2...)
			sk = append(sk, dh3...)

			if tt.withOneTimePrekey {
				dh4, _ := dh25519.GetSharedSecret(aliceEphemeralPrivateKey, bobKeys.OneTimePublicKey)
				sk = append(sk, dh4...)
			}

			// Derive the key using HKDF
			derivedKey, err := hkdf.New32BytesKeyFromSecret(sk)
			assert.NoError(t, err, "error deriving key using HKDF on Alice's side")

			// Check that Bob's derived key matches Alice's derived key
			assert.True(t, equalKeys(key, derivedKey), "Bob's and Alice's derived keys do not match")
		})
	}
}

// Helper functions

type BobKeys struct {
	IdentityPublicKey  key_ed25519.PublicKey
	PrekeyPublicKey    key_ed25519.PublicKey
	OneTimePublicKey   key_ed25519.PublicKey
	IdentityPrivateKey key_ed25519.PrivateKey
	PrekeyPrivateKey   key_ed25519.PrivateKey
	OneTimePrivateKey  key_ed25519.PrivateKey
}

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

	bobKeys := &BobKeys{
		IdentityPublicKey:  *identityPubKey,
		PrekeyPublicKey:    *prekeyPubKey,
		IdentityPrivateKey: *identityKey,
		PrekeyPrivateKey:   *prekey,
	}

	bobBundle := &BobPrekeyBundle{
		IdentityKey: *identityKey,
		Prekey:      *prekey,
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

		bobKeys.OneTimePublicKey = *oneTimePrekeyPubKey
		bobKeys.OneTimePrivateKey = *oneTimePrekey
		bobBundle.OneTimePrekey = oneTimePrekey
	}

	return bobBundle, bobKeys, nil
}

func generateAliceKeys() (*ReceivedAliceKeyBundle, key_ed25519.PrivateKey, key_ed25519.PrivateKey, error) {
	identityKey, err := key_ed25519.New()
	if err != nil {
		return nil, key_ed25519.PrivateKey{}, key_ed25519.PrivateKey{}, err
	}

	ephemeralKey, err := key_ed25519.New()
	if err != nil {
		return nil, key_ed25519.PrivateKey{}, key_ed25519.PrivateKey{}, err
	}

	identityPubKey, err := identityKey.Public()
	if err != nil {
		return nil, key_ed25519.PrivateKey{}, key_ed25519.PrivateKey{}, err
	}

	ephemeralPubKey, err := ephemeralKey.Public()
	if err != nil {
		return nil, key_ed25519.PrivateKey{}, key_ed25519.PrivateKey{}, err
	}

	aliceBundle := &ReceivedAliceKeyBundle{
		IdentityKey:  *identityPubKey,
		EphemeralKey: *ephemeralPubKey,
	}

	return aliceBundle, *identityKey, *ephemeralKey, nil
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
