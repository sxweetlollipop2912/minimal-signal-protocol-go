package doubleratchet

import (
	hmac2 "crypto/hmac"
	"minimal-signal/crypto"
	"minimal-signal/crypto/aes256"
	"minimal-signal/crypto/dh25519"
	"minimal-signal/crypto/hkdf"
	"minimal-signal/crypto/hmac"
	"minimal-signal/crypto/key_ed25519"
)

const (
	// maxSkip is the constant specifying the maximum number of message keys that can be skipped in a single chain
	maxSkip = 20 // TODO: this is a random value
)

var (
	// Salts must be unique for each KDF invocation
	HKDFSaltKDF_RK = []byte("RootKey")
	HKDFSaltAES    = []byte("MessageKey")
)

// DoubleRatchet is the interface is defined in
// https://signal.org/docs/specifications/doubleratchet/#external-functions
type DoubleRatchet interface {
	// GenerateDH returns a new Diffie-Hellman key pair
	GenerateDH() (*key_ed25519.PrivateKey, *key_ed25519.PublicKey, error)

	// DH returns the output from the Diffie-Hellman calculation
	DH(privKey key_ed25519.PrivateKey, pubKey key_ed25519.PublicKey) (*[32]byte, error)

	// KDF_RK returns a pair (32-byte root key, 32-byte chain key) as the output of applying a
	// KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.
	KDF_RK(rk [32]byte, dhOut [32]byte) (rootKey *[32]byte, chainKey *[32]byte, err error)

	// KDF_CK returns a pair (32-byte chain key, 32-byte message key) as the output of applying a
	// KDF keyed by a 32-byte chain key ck to some constant.
	KDF_CK(ck [32]byte) (chainKey *[32]byte, messageKey *[32]byte, err error)

	// Encrypt returns the AEAD encryption of plaintext with message key mk
	Encrypt(mk [32]byte, plaintext []byte, associatedData []byte) (ciphertext []byte, err error)

	// Decrypt returns the AEAD decryption of ciphertext with message key mk
	Decrypt(mk [32]byte, ciphertext []byte, associatedData []byte) (plaintext []byte, err error)

	// Header creates a new message header
	Header(ratchetPub key_ed25519.PublicKey, chainLen uint32, msgNum uint32) (Header, error)

	// Concat encodes a message header into a parseable byte sequence, prepending the ad byte
	Concat(ad []byte, header Header) ([]byte, error)

	// MaxSkip returns the constant specifying the maximum number of message keys that can be skipped in a single chain
	MaxSkip() uint32
}

// doubleRatchetImpl implements the DoubleRatchet interface.
// Defined in https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
type doubleRatchetImpl struct{}

func NewDoubleRatchet() DoubleRatchet {
	return &doubleRatchetImpl{}
}

func (dr *doubleRatchetImpl) GenerateDH() (*key_ed25519.PrivateKey, *key_ed25519.PublicKey, error) {
	priv, err := key_ed25519.New()
	if err != nil {
		return nil, nil, err
	}
	pub, err := priv.Public()
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func (dr *doubleRatchetImpl) DH(privKey key_ed25519.PrivateKey, pubKey key_ed25519.PublicKey) (*[32]byte, error) {
	secret, err := dh25519.GetSecret(privKey, pubKey)
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, ErrInvalidSecretLength
	}
	var secret32 [32]byte
	copy(secret32[:], secret)
	return &secret32, nil
}

func (dr *doubleRatchetImpl) KDF_RK(rk [32]byte, dhOut [32]byte) (*[32]byte, *[32]byte, error) {
	buffer := make([]byte, 64)
	if n, err := hkdf.KDF(crypto.DefaultHashFunc, dhOut[:], rk[:], HKDFSaltKDF_RK, buffer); err != nil {
		return nil, nil, err
	} else if n != 64 {
		return nil, nil, ErrInvalidSecretLength
	}
	var rootKey32 [32]byte
	var chainKey32 [32]byte
	copy(rootKey32[:], buffer[:32])
	copy(chainKey32[:], buffer[32:])
	return &rootKey32, &chainKey32, nil
}

func (dr *doubleRatchetImpl) KDF_CK(ck [32]byte) (*[32]byte, *[32]byte, error) {
	messageKey := hmac.Hash(crypto.DefaultHashFunc, ck[:], []byte{0x01})
	if len(messageKey) != 32 {
		return nil, nil, ErrInvalidSecretLength
	}
	chainKey := hmac.Hash(crypto.DefaultHashFunc, ck[:], []byte{0x02})
	if len(chainKey) != 32 {
		return nil, nil, ErrInvalidSecretLength
	}
	var chainKey32 [32]byte
	var messageKey32 [32]byte
	copy(chainKey32[:], chainKey)
	copy(messageKey32[:], messageKey)
	return &chainKey32, &messageKey32, nil
}

func (dr *doubleRatchetImpl) Encrypt(mk [32]byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	key := make([]byte, 80)
	if n, err := hkdf.KDF(crypto.DefaultHashFunc, mk[:], nil, HKDFSaltAES, key); err != nil {
		return nil, err
	} else if n != 80 {
		return nil, ErrInvalidSecretLength
	}

	var encKey [32]byte
	var authKey [32]byte
	var iv [16]byte
	copy(encKey[:], key[:32])
	copy(authKey[:], key[32:64])
	copy(iv[:], key[64:])

	ciphertext, err := aes256.Encrypt(plaintext, encKey, iv)
	if err != nil {
		return nil, err
	}

	// HMAC input is the associated_data prepended to the ciphertext
	tag := hmac.Hash(crypto.DefaultHashFunc, authKey[:], append(associatedData, ciphertext...))
	return append(ciphertext, tag...), nil
}

func (dr *doubleRatchetImpl) Decrypt(mk [32]byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
	key := make([]byte, 80)
	if n, err := hkdf.KDF(crypto.DefaultHashFunc, mk[:], nil, HKDFSaltAES, key); err != nil {
		return nil, err
	} else if n != 80 {
		return nil, ErrInvalidSecretLength
	}

	var encKey [32]byte
	var authKey [32]byte
	var iv [16]byte
	copy(encKey[:], key[:32])
	copy(authKey[:], key[32:64])
	copy(iv[:], key[64:])

	plaintext, err := aes256.Decrypt(ciphertext[:], encKey, iv)
	if err != nil {
		return nil, err
	}

	// Verify the tag
	tag := hmac.Hash(crypto.DefaultHashFunc, authKey[:], append(associatedData, ciphertext...))
	if !hmac2.Equal(tag, ciphertext[len(ciphertext)-crypto.DefaultHashBlockSize:]) {
		return nil, ErrInvalidTag
	}

	return plaintext, nil
}

func (dr *doubleRatchetImpl) Header(ratchetPub key_ed25519.PublicKey, chainLen uint32, msgNum uint32) (Header, error) {
	return Header{
		RatchetPub: ratchetPub,
		ChainLen:   chainLen,
		MsgNum:     msgNum,
	}, nil
}

func (dr *doubleRatchetImpl) Concat(ad []byte, header Header) ([]byte, error) {
	headerBytes, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	return append(ad, headerBytes...), nil
}

func (dr *doubleRatchetImpl) MaxSkip() uint32 {
	return maxSkip
}
