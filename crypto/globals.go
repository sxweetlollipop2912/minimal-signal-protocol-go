package crypto

import "crypto/sha256"

var (
	DefaultHashFunc = sha256.New
)

const (
	HMACSHA256Size = 32
)
