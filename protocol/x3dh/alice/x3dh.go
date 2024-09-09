package alice

import (
	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/key_ed25519"
)

// https://signal.org/docs/specifications/x3dh/
// Terminology:
// - Alice: sender
// - Bob: receiver

func PerformKeyAgreement(bob *BobPublicPrekeyBundle, aliceIdKey key_ed25519.PrivateKey) (sharedKey []byte, ephPubKey *key_ed25519.PublicKey, err error) {
	var (
		alice = aliceKeyBundle{
			IdentityKey: aliceIdKey,
		}
		aliceEphPubKeyPtr *key_ed25519.PublicKey
		sk                []byte
	)

	// 1. Alice verifies Bob's signature
	if err = bob.Verify(); err != nil {
		return nil, nil, err
	}

	// 2. Alice generates an ephemeral key pair
	ephKeyPtr, err := key_ed25519.New()
	if err != nil {
		return nil, nil, err
	}
	alice.EphemeralKey = *ephKeyPtr

	aliceEphPubKeyPtr, err = alice.EphemeralKey.Public()
	if err != nil {
		return nil, nil, err
	}

	// 3. Alice computes the shared secret
	dh1, err := dh25519.GetSharedSecret(alice.IdentityKey, bob.Prekey)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := dh25519.GetSharedSecret(alice.EphemeralKey, bob.IdentityKey)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := dh25519.GetSharedSecret(alice.EphemeralKey, bob.Prekey)
	if err != nil {
		return nil, nil, err
	}

	var dh4 []byte
	if bob.OneTimePrekey != nil {
		if dh4, err = dh25519.GetSharedSecret(alice.EphemeralKey, *bob.OneTimePrekey); err != nil {
			dh4 = nil
		}
	}
	if dh4 != nil {
		// If Bob provides one-time key
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3)+len(dh4))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
		sk = append(sk, dh4...)
	} else {
		// If Bob doesn't provide one-time key
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
	}

	// 4. Alice derives the key
	sharedKey, err = hkdf.New32BytesKeyFromSecret(sk)
	if err != nil {
		return nil, nil, err
	}

	return sharedKey, aliceEphPubKeyPtr, nil
}
