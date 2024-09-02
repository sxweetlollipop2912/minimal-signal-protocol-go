package bob

import (
	"minimal-signal/crypto/key_ed25519"
)

type BobPrekeyBundle struct {
	IdentityKey   key_ed25519.PrivateKey
	Prekey        key_ed25519.PrivateKey
	OneTimePrekey *key_ed25519.PrivateKey // optional
}

type AliceKeyBundle struct {
	IdentityKey  key_ed25519.PublicKey
	EphemeralKey key_ed25519.PublicKey
}
