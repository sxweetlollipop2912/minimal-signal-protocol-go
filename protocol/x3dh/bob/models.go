package bob

import (
	"fmt"
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/crypto/signer_schnorr"
	"minimal-signal/protocol/x3dh/alice"
)

type BobPrekeyBundle struct {
	IdentityKey   key_ed25519.PrivateKey
	Prekey        key_ed25519.PrivateKey
	OneTimePrekey *key_ed25519.PrivateKey // optional
}

type ReceivedAliceKeyBundle struct {
	IdentityKey  key_ed25519.PublicKey
	EphemeralKey key_ed25519.PublicKey
}

func (bob *BobPrekeyBundle) ToPublicBundle() (alice.ReceivedBobPrekeyBundle, error) {
	identityKeyPub, err := bob.IdentityKey.Public()
	if err != nil {
		return alice.ReceivedBobPrekeyBundle{}, fmt.Errorf("failed to get public identity key: %w", err)
	}

	prekeyPub, err := bob.Prekey.Public()
	if err != nil {
		return alice.ReceivedBobPrekeyBundle{}, fmt.Errorf("failed to get public prekey: %w", err)
	}

	// var oneTimePrekeyPub *key_ed25519.PublicKey
	// if bob.OneTimePrekey != nil {
	// 	oneTimePrekeyPub, err = bob.OneTimePrekey.Public()
	// 	if err != nil {
	// 		return alice.ReceivedBobPrekeyBundle{}, fmt.Errorf("failed to get public one-time prekey: %w", err)
	// 	}
	// }

	prekeySig, err := signer_schnorr.Sign(bob.IdentityKey, prekeyPub[:])
	if err != nil {
		return alice.ReceivedBobPrekeyBundle{}, fmt.Errorf("failed to sign prekey: %w", err)
	}

	return alice.ReceivedBobPrekeyBundle{
		IdentityKey:   *identityKeyPub,
		Prekey:        *prekeyPub,
		PrekeySig:     prekeySig,
		OneTimePrekey: nil,
	}, nil
}
