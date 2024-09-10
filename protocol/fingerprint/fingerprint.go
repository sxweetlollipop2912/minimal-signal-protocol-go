package fingerprint

import (
	"crypto/sha512"
	"encoding/binary"
	"minimal-signal/crypto/key_ed25519"
)

// Fingerprint impl mimics what Signal app actually does
func Fingerprint(pubKey key_ed25519.PublicKey, userIdentifier []byte) (*[30]int, error) {
	digest := append(pubKey[:], userIdentifier...)
	hash := sha512.New()
	for i := 0; i < 5200; i++ {
		_, err := hash.Write(digest)
		if err != nil {
			return nil, err
		}
		digest = hash.Sum(nil)
		hash.Reset()
	}

	var result [30]byte
	copy(result[:], digest[:30])

	var finalResult [30]int
	for i := 0; i < 6; i++ {
		chunk := result[i*5 : (i+1)*5]
		num := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, chunk...)) % 100000
		for j := 4; j >= 0; j-- {
			finalResult[i*5+j] = int(num % 10)
			num /= 10
		}
	}

	return &finalResult, nil
}
