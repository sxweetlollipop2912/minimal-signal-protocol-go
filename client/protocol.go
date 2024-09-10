package client

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"minimal-signal/common"
	"minimal-signal/configs"
	"minimal-signal/crypto/key_ed25519"
	"minimal-signal/protocol/doubleratchet"
	"minimal-signal/protocol/fingerprint"
	"minimal-signal/protocol/x3dh/alice"
	"minimal-signal/protocol/x3dh/bob"
)

// signalAliceHandshake performs the key agreement protocol and init ratchet.
// Must already have recipientID set.
// Postcondition: ratchets are established
func (app *ChatApp) signalAliceHandshake() error {
	sharedKey, pubEphKey, err := alice.PerformKeyAgreement(&app.otherIDKeyBundle, app.userPrivKeyBundle.IdentityKey)
	if err != nil {
		return fmt.Errorf("failed to perform key agreement: %w", err)
	}
	var ratchetKey [32]byte
	copy(ratchetKey[:], sharedKey)
	app.ratchet, err = doubleratchet.InitAlice(ratchetKey, app.otherIDKeyBundle.Prekey)
	if err != nil {
		return fmt.Errorf("failed to init ratchet: %w", err)
	}

	app.initHandshake = &common.X3DHHandshakeBundle{
		EphPubKey:     *pubEphKey,
		OneTimePubKey: app.otherIDKeyBundle.OneTimePrekey,
	}
	return nil
}

func (app *ChatApp) signalBobHandshake(aliceDHKeys *common.X3DHHandshakeBundle, aliceIDKey *key_ed25519.PublicKey) error {
	// X3DH
	// Assume we don't use one-time key
	sharedKey, err := bob.PerformKeyAgreement(&app.userPrivKeyBundle, &bob.ReceivedAliceKeyBundle{
		IdentityKey:  *aliceIDKey,
		EphemeralKey: aliceDHKeys.EphPubKey,
	})
	if err != nil {
		return fmt.Errorf("failed to perform key agreement: %w", err)
	}
	var ratchetKey [32]byte
	copy(ratchetKey[:], sharedKey)

	bobPrekeyPub, err := app.userPrivKeyBundle.Prekey.Public()
	if err != nil {
		return fmt.Errorf("failed to get prekey public key: %w", err)
	}
	app.ratchet = doubleratchet.InitBob(ratchetKey, key_ed25519.Pair{
		Pub:  *bobPrekeyPub,
		Priv: app.userPrivKeyBundle.Prekey,
	})
	return nil
}

func (app *ChatApp) encryptMessage(msg string) (*common.MessageBundle, error) {
	// handshake
	firstTime := false
	if app.ratchet == nil {
		firstTime = true
		if err := app.signalAliceHandshake(); err != nil {
			return nil, fmt.Errorf("failed to perform handshake: %w", err)
		}
	}

	// Encrypt message
	ad, err := app.getADBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get AD bytes: %w", err)
	}

	// Forward DH ratchet with chance
	var forwardDH bool
	if r, err := rand.Int(rand.Reader, big.NewInt(int64(configs.ForwardDHRatchetChanceTotal))); err != nil {
		forwardDH = true
	} else {
		forwardDH = r.Int64() == 0
	}
	header, encryptedMessage, err := app.ratchet.Encrypt([]byte(msg), ad[:], forwardDH && (!firstTime))
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %w", err)
	}

	return &common.MessageBundle{
		From:      app.userID,
		To:        app.recipientID,
		Message:   encryptedMessage,
		Header:    *header,
		AD:        ad,
		Handshake: app.initHandshake,
	}, nil
}

func (app *ChatApp) decryptMessage(msg *common.MessageBundle) ([]byte, error) {
	if app.ratchet == nil {
		if err := app.signalBobHandshake(msg.Handshake, &app.otherIDKeyBundle.IdentityKey); err != nil {
			return nil, fmt.Errorf("error performing handshake: %w", err)
		}
	}
	// Decrypt message
	plaintext, err := app.ratchet.Decrypt(msg.Header, msg.Message, msg.AD[:])
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %vw", err)
	}
	return plaintext, nil
}

func (app *ChatApp) fingerprint() (string, error) {
	userIDPub, err := app.userPrivKeyBundle.IdentityKey.Public()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}
	fingerprint1, err := fingerprint.Fingerprint(*userIDPub, []byte(app.userID))
	if err != nil {
		return "", fmt.Errorf("failed to get fingerprint: %w", err)
	}
	fingerprint2, err := fingerprint.Fingerprint(app.otherIDKeyBundle.IdentityKey, []byte(app.recipientID))
	if err != nil {
		return "", fmt.Errorf("failed to get fingerprint: %w", err)
	}
	if app.userID > app.recipientID {
		// swap
		fingerprint1, fingerprint2 = fingerprint2, fingerprint1
	}

	// Concatenate the two fingerprints
	var combined [60]int
	copy(combined[:30], fingerprint1[:])
	copy(combined[30:], fingerprint2[:])

	// Convert to string with spaces every 5 digits
	var result string
	for i, num := range combined {
		result += fmt.Sprintf("%d", num)
		if (i+1)%5 == 0 && i != len(combined)-1 {
			result += " "
		}
	}
	return result, nil
}
