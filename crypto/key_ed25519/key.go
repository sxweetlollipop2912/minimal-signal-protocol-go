package key_ed25519

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
)

type (
	// PrivateKey is a 32-byte private key
	PrivateKey []byte
	// PublicKey is a 32-byte public key
	PublicKey []byte
	Pair      struct {
		Priv PrivateKey
		Pub  PublicKey
	}
)

var (
	Suite = suites.MustFind("Ed25519") // Use the edwards25519-curve
)

func New() (PrivateKey, error) {
	privK := Suite.Scalar().Pick(Suite.RandomStream())
	return privK.MarshalBinary()
}

func (privB PrivateKey) Public() (PublicKey, error) {
	privK, err := privB.ToScalar()
	if err != nil {
		return nil, err
	}
	pubK := Suite.Point().Mul(privK, nil)
	return pubK.MarshalBinary()
}

func (privB PrivateKey) ToScalar() (kyber.Scalar, error) {
	privK := Suite.Scalar()
	if err := privK.UnmarshalBinary(privB); err != nil {
		return nil, err
	}
	return privK, nil
}

func (pubB PublicKey) ToPoint() (kyber.Point, error) {
	pubK := Suite.Point()
	if err := pubK.UnmarshalBinary(pubB); err != nil {
		return nil, err
	}
	return pubK, nil
}
