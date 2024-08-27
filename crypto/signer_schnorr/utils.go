package signer_schnorr

import (
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"minimal-signal/crypto/key_ed25519"
)

func Sign(privKey key_ed25519.PrivateKey, msg []byte) ([]byte, error) {
	privScalar, err := privKey.ToScalar()
	if err != nil {
		return nil, err
	}
	return schnorr.Sign(key_ed25519.Suite, privScalar, msg)
}

func Verify(pubKey key_ed25519.PublicKey, msg, sig []byte) error {
	pubPoint, err := pubKey.ToPoint()
	if err != nil {
		return err
	}
	return schnorr.Verify(key_ed25519.Suite, pubPoint, msg, sig)
}
