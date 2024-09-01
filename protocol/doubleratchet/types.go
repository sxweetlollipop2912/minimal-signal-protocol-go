package doubleratchet

import "minimal-signal/crypto/key_ed25519"

type Header struct {
	RatchetPub key_ed25519.PublicKey
	ChainLen   uint32
	MsgNum     uint32
}
