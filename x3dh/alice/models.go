package alice

import (
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/crypto/signer_schnorr"
)

type BobPrekeyBundle struct {
	IdentityKey   key_ed25519.PublicKey
	Prekey        key_ed25519.PublicKey
	PrekeySig     []byte
	OneTimePrekey key_ed25519.PublicKey // optional
}

type AliceKeyBundle struct {
	IdentityKey  key_ed25519.PrivateKey
	EphemeralKey key_ed25519.PrivateKey
}

func (bob *BobPrekeyBundle) Verify() error {
	return signer_schnorr.Verify(bob.IdentityKey, bob.Prekey, bob.PrekeySig)
}
