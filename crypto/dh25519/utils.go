package dh25519

import (
	"minimal-signal/crypto/key_ed25519"
)

func GetSharedSecret(APrivKey key_ed25519.PrivateKey, BPubKey key_ed25519.PublicKey) ([]byte, error) {
	privScalar, err := APrivKey.ToScalar()
	if err != nil {
		return nil, err
	}
	pubPoint, err := BPubKey.ToPoint()
	if err != nil {
		return nil, err
	}
	secretPoint := key_ed25519.Suite.Point().Mul(privScalar, pubPoint)
	return secretPoint.MarshalBinary()
}
