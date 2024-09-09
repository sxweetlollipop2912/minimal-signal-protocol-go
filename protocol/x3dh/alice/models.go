package alice

import (
	"encoding/json"
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/crypto/signer_schnorr"
)

type ReceivedBobPrekeyBundle struct {
	IdentityKey   key_ed25519.PublicKey
	Prekey        key_ed25519.PublicKey
	PrekeySig     []byte
	OneTimePrekey *key_ed25519.PublicKey // optional
}

type AliceKeyBundle struct {
	IdentityKey  key_ed25519.PrivateKey
	EphemeralKey key_ed25519.PrivateKey
}

func (bob ReceivedBobPrekeyBundle) Verify() error {
	return signer_schnorr.Verify(bob.IdentityKey, bob.Prekey[:], bob.PrekeySig)
}

func (bob ReceivedBobPrekeyBundle) MarshalBinary() ([]byte, error) {
	return json.Marshal(bob)
}

func (bob ReceivedBobPrekeyBundle) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &bob)
}
