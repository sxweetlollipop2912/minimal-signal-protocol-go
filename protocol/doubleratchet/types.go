package doubleratchet

import (
	"encoding/json"
	"minimal-signal/crypto/key_ed25519"
)

type (
	MsgIndex   uint32
	MsgKey     [32]byte
	RatchetKey [32]byte
)

type Header struct {
	RatchetPub key_ed25519.PublicKey
	// Pn is the number of messages in previous chain
	Pn MsgIndex
	// N is the message number
	N MsgIndex
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
	return h.RatchetPub.Equals(&other.RatchetPub) && h.Pn == other.Pn && h.N == other.N
}

func (h *Header) Marshal() ([]byte, error) {
	return json.Marshal(h)
}

// State ref: https://signal.org/docs/specifications/doubleratchet/#state-variables
type state struct {
	// dhs is the DH Ratchet key pair (the “sending” or “self” ratchet key)
	dhs key_ed25519.Pair
	// dhr is the DH Ratchet public key (the “received” or “remote” key)
	// Not initialized at the beginning for Bob
	dhr *key_ed25519.PublicKey
	// rk is the 32-byte Root Key
	rk RatchetKey
	// cks and ckr are 32-byte Chain Keys for sending and receiving
	// cks is not initialized at the beginning for Bob
	// ckr is not initialized at the beginning for both Bob and Alice
	cks, ckr *RatchetKey
	// ns and nr are message numbers for sending and receiving
	ns, nr MsgIndex
	// pn is the number of messages in previous sending chain
	pn MsgIndex
	// mkSkipped is a map of skipped-over message keys, indexed by ratchet public key and message number
	mkSkipped map[mkSkippedKey]*MsgKey
}

type mkSkippedKey struct {
	RatchetPub key_ed25519.PublicKey
	N          MsgIndex
}
