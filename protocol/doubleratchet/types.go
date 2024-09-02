package doubleratchet

import (
	"encoding/json"
	"minimal-signal/crypto/key_ed25519"
)

type Header struct {
	RatchetPub key_ed25519.PublicKey
	ChainLen   uint32
	MsgNum     uint32
}

func UnmarshalHeader(data []byte) (*Header, error) {
	var h Header
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (h *Header) Equals(other *Header) bool {
	if h == nil || other == nil {
		return false
	}
	return h.RatchetPub.Equals(&other.RatchetPub) && h.ChainLen == other.ChainLen && h.MsgNum == other.MsgNum
}

func (h *Header) Marshal() ([]byte, error) {
	return json.Marshal(h)
}

// State ref: https://signal.org/docs/specifications/doubleratchet/#state-variables
type State struct {
	dhs          key_ed25519.Pair
	dhr          key_ed25519.PublicKey
	rk, cks, ckr [32]byte
	ns, nr       uint32
	pn           uint32
	// mkSkipped is a map of skipped-over message keys, indexed by ratchet public key and message number
	mkSkipped map[[32]byte]map[uint32][32]byte
}
