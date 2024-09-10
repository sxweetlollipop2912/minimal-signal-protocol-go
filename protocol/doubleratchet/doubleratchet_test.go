package doubleratchet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"minimal-signal/crypto/key_ed25519"
)

func TestDoubleRatchet(t *testing.T) {
	type testCase struct {
		name              string
		associatedData    []byte
		aliceMessage      []byte
		bobMessage        []byte
		tamperMessage     bool
		expectDecryptFail bool
	}

	testCases := []testCase{
		{
			name:              "successful ratchet message exchange",
			associatedData:    []byte("test associated data"),
			aliceMessage:      []byte("Hello, Bob!"),
			bobMessage:        []byte("Hi, Alice!"),
			tamperMessage:     false,
			expectDecryptFail: false,
		},
		{
			name:              "decrypt failure with tampered message",
			associatedData:    []byte("test associated data"),
			aliceMessage:      []byte("Hello, Bob!"),
			bobMessage:        []byte("Hi, Alice!"),
			tamperMessage:     true,
			expectDecryptFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate random keys for Alice
			aliceSK, err := key_ed25519.New()
			assert.NoError(t, err)

			// Generate random keys for Bob
			bobSK, err := key_ed25519.New()
			assert.NoError(t, err)

			bobPub, err := bobSK.Public()
			assert.NoError(t, err)

			// Init Alice's and Bob's ratchets
			aliceRatchet, err := InitAlice(RatchetKey(*aliceSK), *bobPub)
			assert.NoError(t, err)

			bobRatchet := InitBob(RatchetKey(*aliceSK), key_ed25519.Pair{Priv: *bobSK, Pub: *bobPub})

			// Step 1: Alice encrypts and sends a message to Bob
			header, aliceCiphertext, err := aliceRatchet.Encrypt(tc.aliceMessage, tc.associatedData, false)
			assert.NoError(t, err)

			// Optionally tamper with the ciphertext
			if tc.tamperMessage {
				aliceCiphertext[0] ^= 0xff // Tamper with the first byte of the ciphertext
			}

			// Bob decrypts the message from Alice
			plaintext, err := bobRatchet.Decrypt(*header, aliceCiphertext, tc.associatedData)
			if tc.expectDecryptFail {
				assert.Error(t, err, "Decryption should have failed due to tampered message")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.aliceMessage, plaintext)
			}

			// Step 2: Alice sends another message to Bob
			header2, aliceCiphertext2, err := aliceRatchet.Encrypt([]byte("Second message from Alice"), tc.associatedData, false)
			assert.NoError(t, err)

			// Bob decrypts the second message
			plaintext2, err := bobRatchet.Decrypt(*header2, aliceCiphertext2, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, []byte("Second message from Alice"), plaintext2)

			// Step 3: Bob sends a message back to Alice
			headerBob, bobCiphertext, err := bobRatchet.Encrypt(tc.bobMessage, tc.associatedData, false)
			assert.NoError(t, err)

			// Alice decrypts Bob's message
			plaintextBob, err := aliceRatchet.Decrypt(*headerBob, bobCiphertext, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, tc.bobMessage, plaintextBob)

			// Step 4: Alice sends another message without advancing the DH ratchet
			headerAliceNoRatchet, aliceCiphertextNoRatchet, err := aliceRatchet.Encrypt([]byte("Third message without DH ratchet"), tc.associatedData, false)
			assert.NoError(t, err)

			// Bob decrypts Alice's message
			plaintextAliceNoRatchet, err := bobRatchet.Decrypt(*headerAliceNoRatchet, aliceCiphertextNoRatchet, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, []byte("Third message without DH ratchet"), plaintextAliceNoRatchet)

			// Step 5: Alice sends another message (this time with DH ratchet advance)
			headerAliceRatchet, aliceCiphertextRatchet, err := aliceRatchet.Encrypt([]byte("Fourth message with DH ratchet"), tc.associatedData, true)
			assert.NoError(t, err)

			// Bob decrypts the fourth message
			plaintextAliceRatchet, err := bobRatchet.Decrypt(*headerAliceRatchet, aliceCiphertextRatchet, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, []byte("Fourth message with DH ratchet"), plaintextAliceRatchet)

			// Step 6: Bob advances the DH ratchet using Decrypt and sends a message to Alice
			headerBobRatchet, bobCiphertextRatchet, err := bobRatchet.Encrypt([]byte("Bob's second message with DH ratchet"), tc.associatedData, true)
			assert.NoError(t, err)

			// Alice decrypts Bob's second message with DH ratchet
			plaintextBobRatchet, err := aliceRatchet.Decrypt(*headerBobRatchet, bobCiphertextRatchet, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, []byte("Bob's second message with DH ratchet"), plaintextBobRatchet)

			// Step 7: Alice sends a message to Bob without advancing the DH ratchet again
			headerAliceNoRatchet2, aliceCiphertextNoRatchet2, err := aliceRatchet.Encrypt([]byte("Fifth message without DH ratchet"), tc.associatedData, false)
			assert.NoError(t, err)

			// Bob decrypts Alice's message
			plaintextAliceNoRatchet2, err := bobRatchet.Decrypt(*headerAliceNoRatchet2, aliceCiphertextNoRatchet2, tc.associatedData)
			assert.NoError(t, err)
			assert.Equal(t, []byte("Fifth message without DH ratchet"), plaintextAliceNoRatchet2)
		})
	}
}

func TestDHRatchetSendAndReceiveChain(t *testing.T) {
	// Step 1: Generate DH key pairs for Alice and Bob
	aliceDHKeyPair, err := key_ed25519.New()
	assert.NoError(t, err)

	bobDHKeyPair, err := key_ed25519.New()
	assert.NoError(t, err)

	// Step 2: Get Alice's and Bob's public keys (handling error)
	alicePubKey, err := aliceDHKeyPair.Public()
	assert.NoError(t, err)

	bobPubKey, err := bobDHKeyPair.Public()
	assert.NoError(t, err)

	// Step 3: Generate a random root key (Rk) for both Alice and Bob
	var randomRootKey RatchetKey
	for i := range randomRootKey {
		randomRootKey[i] = byte(i) // Simple key for consistency in testing
	}

	// Step 4: Set up Alice's initial State
	// Alice's State includes Bob's public key in Dhr, allowing her to perform DH calculations with Bob
	aliceState := &State{
		Dhs:       key_ed25519.Pair{Priv: *aliceDHKeyPair, Pub: *alicePubKey}, // Alice's own key pair
		Dhr:       bobPubKey,                                                  // Bob's public key for Alice's DH calculations
		Rk:        randomRootKey,                                              // Shared root key
		Cks:       nil,                                                        // Not initialized until the ratchet is advanced
		MkSkipped: make(map[MkSkippedKey]*MsgKey),
		Ns:        0, // Alice starts with 0 sent messages
	}

	// Step 5: Set up Bob's initial State
	// Bob's State includes Alice's public key in Dhr
	bobState := &State{
		Dhs:       key_ed25519.Pair{Priv: *bobDHKeyPair, Pub: *bobPubKey}, // Bob's own key pair
		Dhr:       alicePubKey,                                            // Alice's public key for Bob's DH calculations
		Rk:        randomRootKey,                                          // Shared root key
		Ckr:       nil,                                                    // Not initialized until Bob advances the ratchet
		MkSkipped: make(map[MkSkippedKey]*MsgKey),
		Nr:        0, // Bob starts with 0 received messages
	}

	// Step 6: Alice performs a DH ratchet send chain
	err = dhRatchetSendChain(aliceState)
	assert.NoError(t, err)

	// Step 7: Bob receives Alice's new public key via header and performs a DH ratchet receive chain
	header := Header{
		RatchetPub: aliceState.Dhs.Pub, // Alice's new public key
	}
	err = dhRatchetReceiveChain(bobState, &header)
	assert.NoError(t, err)

	// Step 8: Assert that Alice's root key (Rk) and Bob's root key (Rk) match after the DH ratchet
	assert.Equal(t, aliceState.Rk, bobState.Rk, "Root keys should match after DH ratchet")

	// Step 9: Assert that Alice's sending chain key (Cks) matches Bob's receiving chain key (Ckr)
	assert.Equal(t, aliceState.Cks, bobState.Ckr, "Alice's send chain key should match Bob's receive chain key")

	// Additional check: Ensure Alice's public key (Dhs) is properly updated for Bob
	assert.Equal(t, aliceState.Dhs.Pub, *bobState.Dhr, "Bob's received public key should match Alice's new DH public key")
}
