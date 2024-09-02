package crypto

import (
	"crypto/sha256"
	"hash"
)

var DefaultHashFunc func() hash.Hash = sha256.New
var DefaultHashBlockSize int = sha256.BlockSize
