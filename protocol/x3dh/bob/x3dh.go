package bob

import (
	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
)

// https://signal.org/docs/specifications/x3dh/
// Terminology:
// - Alice: sender
// - Bob: receiver

func PerformKeyAgreement(bob *BobPrekeyBundle, alice *ReceivedAliceKeyBundle) (sharedKey []byte, err error) {
	var (
		sk []byte
	)
	// 1. Bob computes the shared secret
	dh1, err := dh25519.GetSharedSecret(bob.Prekey, alice.IdentityKey)
	if err != nil {
		return nil, err
	}
	dh2, err := dh25519.GetSharedSecret(bob.IdentityKey, alice.EphemeralKey)
	if err != nil {
		return nil, err
	}
	dh3, err := dh25519.GetSharedSecret(bob.Prekey, alice.EphemeralKey)
	if err != nil {
		return nil, err
	}

	var dh4 []byte
	if bob.OneTimePrekey != nil {
		dh4, err = dh25519.GetSharedSecret(*bob.OneTimePrekey, alice.EphemeralKey)
		if err != nil {
			dh4 = nil
		}
	}
	if dh4 != nil {
		// If Alice didn't use Bob's one-time key
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3)+len(dh4))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
		sk = append(sk, dh4...)
	} else {
		// If Alice used Bob's one-time key
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
	}

	// 2. Bob derives the key
	sharedKey, err = hkdf.New32BytesKeyFromSecret(sk)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}
