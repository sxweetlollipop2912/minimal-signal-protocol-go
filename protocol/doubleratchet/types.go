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
	RatchetPub key_ed25519.PublicKey `json:"ratchet_pub" validate:"required"`
	// Pn is the number of messages in previous chain
	Pn MsgIndex `json:"pn" validate:"required"`
	// N is the message number
	N MsgIndex `json:"n" validate:"required"`
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
type State struct {
	// Dhs is the DH Ratchet key pair (the “sending” or “self” ratchet key)
	Dhs key_ed25519.Pair
	// Dhr is the DH Ratchet public key (the “received” or “remote” key)
	// Not initialized at the beginning for Bob
	Dhr *key_ed25519.PublicKey
	// Rk is the 32-byte Root Key
	Rk RatchetKey
	// Cks and Ckr are 32-byte Chain Keys for sending and receiving
	// Cks is not initialized at the beginning for Bob
	// Ckr is not initialized at the beginning for both Bob and Alice
	Cks, Ckr *RatchetKey
	// Ns and Nr are message numbers for sending and receiving
	Ns, Nr MsgIndex
	// Pn is the number of messages in previous sending chain
	Pn MsgIndex
	// MkSkipped is a map of skipped-over message keys, indexed by ratchet public key and message number
	MkSkipped map[MkSkippedKey]*MsgKey
}

type MkSkippedKey struct {
	RatchetPub key_ed25519.PublicKey
	N          MsgIndex
}
