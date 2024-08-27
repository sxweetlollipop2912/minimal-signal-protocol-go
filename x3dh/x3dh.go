package x3dh

import (
	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/key_ed25519"
)

// https://signal.org/docs/specifications/x3dh/
// Terminology:
// - Alice: sender
// - Bob: receiver

func PerformKeyAgreement(bob *BobPrekeyBundle, aliceIdKey key_ed25519.PrivateKey) (key []byte, ephPubKey key_ed25519.PublicKey, err error) {
	var (
		alice          AliceKeyBundle
		aliceEphPubKey key_ed25519.PublicKey
		sk             []byte
	)
	// 1. Alice verifies Bob's signature
	if err = bob.Verify(); err != nil {
		return nil, nil, err
	}

	// 2. Alice generates an ephemeral key pair
	aliceEphemeralKey, err := key_ed25519.New()
	if err != nil {
		return nil, nil, err
	}
	aliceEphPubKey, err = alice.EphemeralKey.Public()
	if err != nil {
		return nil, nil, err
	}
	alice = AliceKeyBundle{
		IdentityKey:  aliceIdKey,
		EphemeralKey: aliceEphemeralKey,
	}

	// 3. Alice computes the shared secret
	dh1, err := dh25519.GetSecret(&alice.IdentityKey, &bob.Prekey)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := dh25519.GetSecret(&alice.EphemeralKey, &bob.IdentityKey)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := dh25519.GetSecret(&alice.EphemeralKey, &bob.Prekey)
	if err != nil {
		return nil, nil, err
	}
	dh4, err := dh25519.GetSecret(&alice.EphemeralKey, &bob.OneTimePrekey)
	if err != nil {
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
	} else {
		sk = make([]byte, 0, len(dh1)+len(dh2)+len(dh3)+len(dh4))
		sk = append(sk, dh1...)
		sk = append(sk, dh2...)
		sk = append(sk, dh3...)
		sk = append(sk, dh4...)
	}

	// 4. Alice derives the key
	key, err = hkdf.NewFromSecret(sk)
	if err != nil {
		return nil, nil, err
	}
	return key, aliceEphPubKey, nil
}
