package common

import (
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/protocol/doubleratchet"
)

// MessageBundle struct for sending/receiving JSON
type MessageBundle struct {
	From      string               `json:"from" validate:"required"`
	To        string               `json:"to" validate:"required"`
	Message   []byte               `json:"message" validate:"required"`
	Header    doubleratchet.Header `json:"header" validate:"required"`
	AD        [64]byte             `json:"ad" validate:"required"`
	Handshake *X3DHHandshakeBundle `json:"handshake,omitempty"`
}

// X3DHHandshakeBundle is sent in Alice's first message
type X3DHHandshakeBundle struct {
	EphPubKey     key_ed25519.PublicKey  `json:"eph_pub_key" validate:"required"`
	OneTimePubKey *key_ed25519.PublicKey `json:"one_time_pub_key" validate:"required"`
}
