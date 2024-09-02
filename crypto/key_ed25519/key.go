package key_ed25519

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
)

type (
	// PrivateKey is a 32-byte private key
	PrivateKey [32]byte
	// PublicKey is a 32-byte public key
	PublicKey [32]byte
	Pair      struct {
		Priv PrivateKey
		Pub  PublicKey
	}
)

var (
	Suite = suites.MustFind("Ed25519") // Use the edwards25519-curve
)

func New() (*PrivateKey, error) {
	privK := Suite.Scalar().Pick(Suite.RandomStream())
	mutSlicePriv, err := privK.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var privB PrivateKey
	copy(privB[:], mutSlicePriv)
	return &privB, nil
}

func (privB *PrivateKey) Public() (*PublicKey, error) {
	privK, err := privB.ToScalar()
	if err != nil {
		return nil, err
	}
	pubK := Suite.Point().Mul(privK, nil)
	mutSlicePub, err := pubK.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var pubB PublicKey
	copy(pubB[:], mutSlicePub)
	return &pubB, nil
}

func (privB *PrivateKey) ToScalar() (kyber.Scalar, error) {
	privK := Suite.Scalar()
	if err := privK.UnmarshalBinary(privB[:]); err != nil {
		return nil, err
	}
	return privK, nil
}

func (pubB *PublicKey) ToPoint() (kyber.Point, error) {
	pubK := Suite.Point()
	if err := pubK.UnmarshalBinary(pubB[:]); err != nil {
		return nil, err
	}
	return pubK, nil
}

func (pubB *PublicKey) Equals(other *PublicKey) bool {
	if pubB == nil || other == nil {
		return false
	}

	pubBytes := [32]byte(*pubB)
	otherBytes := [32]byte(*other)

	for i := range pubBytes {
		if pubBytes[i] != otherBytes[i] {
			return false
		}
	}
	return true
}
