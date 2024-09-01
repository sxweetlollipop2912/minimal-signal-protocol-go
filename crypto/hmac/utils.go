package hmac

import (
	"crypto/hmac"
	"hash"
)

// Hash returns the HMAC-SHA256 of the data using the key.
func Hash(hash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(hash, key)
	mac.Write(data)
	return mac.Sum(nil)
}
