package signer_schnorr

import (
	"minimal-signal/crypto/key_ed25519"

	"go.dedis.ch/kyber/v4/sign/schnorr"
)

func Sign(privKey key_ed25519.PrivateKey, msg []byte) ([]byte, error) {
	privScalar, err := privKey.ToScalar()
	if err != nil {
		return nil, err
	}
	return schnorr.Sign(key_ed25519.Suite, privScalar, msg)
}

// TODO: Check if this is the correct implementation
func Verify(pubKey key_ed25519.PublicKey, msg, sig []byte) error {
	pubPoint, err := pubKey.ToPoint()
	if err != nil {
		return err
	}
	return schnorr.Verify(key_ed25519.Suite, pubPoint, msg, sig)
}
