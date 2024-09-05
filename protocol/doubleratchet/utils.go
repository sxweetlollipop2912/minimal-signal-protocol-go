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

var (
	// Salts must be unique for each KDF invocation
	HKDFSaltKDF_RK = []byte("RootKey")
	HKDFSaltAES    = []byte("MessageKey")
)

// doubleRatchetUtils is the interface is defined in
// https://signal.org/docs/specifications/doubleratchet/#external-functions
type doubleRatchetUtils interface {
	// generateDH returns a new Diffie-Hellman key pair
	generateDH() (*key_ed25519.Pair, error)

	// dh returns the output from the Diffie-Hellman calculation
	dh(privKey key_ed25519.PrivateKey, pubKey key_ed25519.PublicKey) (*RatchetKey, error)

	// kdfRk returns a pair (32-byte root key, 32-byte chain key) as the output of applying a
	// KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.
	kdfRk(rk RatchetKey, dhOut RatchetKey) (rootKey *RatchetKey, chainKey *RatchetKey, err error)

	// kdfCk returns a pair (32-byte chain key, 32-byte message key) as the output of applying a
	// KDF keyed by a 32-byte chain key ck to some constant.
	kdfCk(ck RatchetKey) (chainKey *RatchetKey, messageKey *MsgKey, err error)

	// encrypt returns the AEAD encryption of plaintext with message key mk
	encrypt(mk MsgKey, plaintext []byte, associatedData []byte) (ciphertext []byte, err error)

	// decrypt returns the AEAD decryption of ciphertext with message key mk
	decrypt(mk MsgKey, ciphertext []byte, associatedData []byte) (plaintext []byte, err error)

	// header creates a new message header
	header(ratchetPub key_ed25519.PublicKey, chainLen MsgIndex, msgNum MsgIndex) (Header, error)

	// concat encodes a message header into a parseable byte sequence, prepending the ad byte
	concat(ad []byte, header Header) ([]byte, error)
}

// doubleRatchetUtilsImpl implements the doubleRatchetUtils interface.
// Defined in https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
type doubleRatchetUtilsImpl struct{}

func newDoubleRatchetUtils() doubleRatchetUtils {
	return &doubleRatchetUtilsImpl{}
}

func (dr *doubleRatchetUtilsImpl) generateDH() (*key_ed25519.Pair, error) {
	priv, err := key_ed25519.New()
	if err != nil {
		return nil, err
	}
	pub, err := priv.Public()
	if err != nil {
		return nil, err
	}
	return &key_ed25519.Pair{
		Priv: *priv,
		Pub:  *pub,
	}, nil
}

func (dr *doubleRatchetUtilsImpl) dh(privKey key_ed25519.PrivateKey, pubKey key_ed25519.PublicKey) (*RatchetKey, error) {
	secret, err := dh25519.GetSharedSecret(privKey, pubKey)
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, ErrInvalidSecretLength
	}
	var secret32 [32]byte
	copy(secret32[:], secret)
	return (*RatchetKey)(&secret32), nil
}

func (dr *doubleRatchetUtilsImpl) kdfRk(rk RatchetKey, dhOut RatchetKey) (*RatchetKey, *RatchetKey, error) {
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
	return (*RatchetKey)(&rootKey32), (*RatchetKey)(&chainKey32), nil
}

func (dr *doubleRatchetUtilsImpl) kdfCk(ck RatchetKey) (*RatchetKey, *MsgKey, error) {
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
	return (*RatchetKey)(&chainKey32), (*MsgKey)(&messageKey32), nil
}

func (dr *doubleRatchetUtilsImpl) encrypt(mk MsgKey, plaintext []byte, associatedData []byte) ([]byte, error) {
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

func (dr *doubleRatchetUtilsImpl) decrypt(mk MsgKey, ciphertext []byte, associatedData []byte) ([]byte, error) {
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

func (dr *doubleRatchetUtilsImpl) header(ratchetPub key_ed25519.PublicKey, chainLen MsgIndex, msgNum MsgIndex) (Header, error) {
	return Header{
		RatchetPub: ratchetPub,
		Pn:         chainLen,
		N:          msgNum,
	}, nil
}

func (dr *doubleRatchetUtilsImpl) concat(ad []byte, header Header) ([]byte, error) {
	headerBytes, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	return append(ad, headerBytes...), nil
}
