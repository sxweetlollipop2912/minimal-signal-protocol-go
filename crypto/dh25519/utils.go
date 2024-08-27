package dh25519

import (
	"errors"
	"minimal-signal/crypto/key_ed25519"
)

var (
	ErrInvalid = errors.New("invalid input")
)

func GetSecret(APrivKey *key_ed25519.PrivateKey, BPubKey *key_ed25519.PublicKey) ([]byte, error) {
	if APrivKey == nil || BPubKey == nil {
		return nil, ErrInvalid
	}
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
