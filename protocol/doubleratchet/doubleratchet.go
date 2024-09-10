package doubleratchet

import (
	"minimal-signal/crypto/key_ed25519"
)

const (
	// maxSkip is the constant specifying the maximum number of message keys that can be skipped in a single chain
	maxSkip = 1000
)

var (
	utils = newDoubleRatchetUtils()
)

// https://signal.org/docs/specifications/doubleratchet/#encrypting-messages and
// https://signal.org/docs/specifications/doubleratchet/#decrypting-messages
type DoubleRatchet struct {
	CurrentState *State
}

func newDoubleRatchet(initState *State) *DoubleRatchet {
	if initState.MkSkipped == nil {
		initState.MkSkipped = make(map[MkSkippedKey]*MsgKey)
	}
	return &DoubleRatchet{
		CurrentState: initState,
	}
}

// InitAlice initializes the Double Ratchet for the sender
func InitAlice(sk RatchetKey, bobDHPubKey key_ed25519.PublicKey) (*DoubleRatchet, error) {
	utils := newDoubleRatchetUtils()

	// Init Dhs
	dhs, err := utils.generateDH()
	if err != nil {
		return nil, err
	}

	// Init Dhr
	dhr := bobDHPubKey

	// Init Rk, Cks
	kdfRkInput, err := utils.dh(dhs.Priv, dhr)
	if err != nil {
		return nil, err
	}
	rk, cks, err := utils.kdfRk(sk, *kdfRkInput)
	if err != nil {
		return nil, err
	}

	return newDoubleRatchet(&State{
		Dhs:       *dhs,
		Dhr:       &dhr,
		Rk:        *rk,
		Cks:       cks,
		MkSkipped: make(map[MkSkippedKey]*MsgKey),
		// Ckr, Ns, Nr, Pn, MkSkipped are init as zero values
	}), nil
}

// InitBob initializes the Double Ratchet for the receiver
func InitBob(sk RatchetKey, bobDHKeyPair key_ed25519.Pair) *DoubleRatchet {
	return newDoubleRatchet(&State{
		Dhs:       bobDHKeyPair,
		Rk:        sk,
		MkSkipped: make(map[MkSkippedKey]*MsgKey),
		// Dhr, Cks, Ckr, Ns, Nr, Pn, MkSkipped are init as zero values
	})
}

// Encrypt is the exported function that performs a symmetric-key ratchet step, then encrypts the message with the
// resulting message key. In addition to the message’s plaintext it takes an AD byte sequence which is prepended
// to the header to form the associated data for the underlying AEAD encryption.
//
// If forwardDHRatchet is true, this function performs a DH ratchet step before the symmetric-key ratchet step.
// Don't set to true on first message.
func (dr *DoubleRatchet) Encrypt(plaintext []byte, associatedData []byte, forwardDHRatchet bool) (*Header, []byte, error) {
	var (
		mk  *MsgKey
		err error
	)

	// 0. If forwardDHRatchet is true, perform a DH ratchet step
	if forwardDHRatchet || dr.CurrentState.Cks == nil {
		if err := dhRatchetSendChain(dr.CurrentState); err != nil {
			return nil, nil, err
		}
	}

	// 1. Generate current message key & update chain key
	dr.CurrentState.Cks, mk, err = utils.kdfCk(*dr.CurrentState.Cks)
	if err != nil {
		return nil, nil, err
	}

	// 2. Create header & its byte sequence
	header := Header{
		RatchetPub: dr.CurrentState.Dhs.Pub,
		Pn:         dr.CurrentState.Pn,
		N:          dr.CurrentState.Ns,
	}

	// 3. Update State.Ns
	dr.CurrentState.Ns++

	// 4. Encrypt plaintext w/ header + associatedData
	ad, err := utils.concat(associatedData, header)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := utils.encrypt(*mk, plaintext, ad)
	if err != nil {
		return nil, nil, err
	}

	return &header, ciphertext, nil
}

// Decrypt is the exported function that decrypts messages. It does the following:
// • If the message corresponds to a skipped message key this function decrypts the message,
// deletes the message key, and returns.
// • Otherwise, if a new ratchet key has been received this function stores any skipped message keys from the
// receiving chain and performs a DH ratchet step to replace the sending and receiving chains.
// • This function then stores any skipped message keys from the current receiving chain, performs a symmetric-key
// ratchet step to derive the relevant message key and next chain key, and decrypts the message.
// If an exception is raised (e.g. message authentication failure) then the message is discarded and changes to
// the State object are discarded. Otherwise, accept the decrypted plaintext and store changes to the State object.
func (dr *DoubleRatchet) Decrypt(header Header, ciphertext []byte, associatedData []byte) ([]byte, error) {
	var (
		// If no error occurs, dr.CurrentState will be updated with newState
		newState = *dr.CurrentState
		mk       *MsgKey
	)
	// 1. Try to decrypt with skipped message keys
	plaintext, err := trySkippedMessageKeys(&newState, &header, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}
	if plaintext != nil {
		return plaintext, nil
	}

	// 2. If a new ratchet key has been received, save skipped message keys from the receiving chain and
	// perform a DH ratchet step
	if newState.Dhr == nil {
		if err := dhRatchetReceiveChain(&newState, &header); err != nil {
			return nil, err
		}

	} else if header.RatchetPub != *newState.Dhr {
		// If a new ratchet key has been received
		if err := dr.skipMessageKeys(&newState, header.Pn); err != nil {
			return nil, err
		}
		if err := dhRatchetReceiveChain(&newState, &header); err != nil {
			return nil, err
		}
	}

	// 3. Store skipped message keys from the current receiving chain if needed
	if err := dr.skipMessageKeys(&newState, header.N); err != nil {
		return nil, err
	}

	// 4. Get message key
	newState.Ckr, mk, err = utils.kdfCk(*newState.Ckr)
	if err != nil {
		return nil, err
	}
	newState.Nr++

	// 5. Update State
	dr.CurrentState = &newState

	// 6. Decrypt
	adHeader, err := utils.concat(associatedData, header)
	if err != nil {
		return nil, err
	}
	return utils.decrypt(*mk, ciphertext, adHeader)
}

// MaxSkip returns the constant specifying the maximum number of message keys that can be skipped in a single chain
func (dr *DoubleRatchet) MaxSkip() MsgIndex {
	return maxSkip
}

func (dr *DoubleRatchet) skipMessageKeys(newState *State, until MsgIndex) error {
	if newState.Nr+dr.MaxSkip() < until {
		return ErrSkippingTooManyKeys
	}

	if newState.Ckr != nil {
		for newState.Nr < until {
			var mk *MsgKey
			var err error
			newState.Ckr, mk, err = utils.kdfCk(*newState.Ckr)
			if err != nil {
				return err
			}
			newState.MkSkipped[MkSkippedKey{
				RatchetPub: *newState.Dhr,
				N:          newState.Nr,
			}] = mk
			newState.Nr++
		}
	}
	return nil
}

func trySkippedMessageKeys(newState *State, header *Header, ciphertext, AD []byte) ([]byte, error) {
	if mk, exists := newState.MkSkipped[MkSkippedKey{
		RatchetPub: header.RatchetPub,
		N:          header.N,
	}]; exists {
		delete(newState.MkSkipped, MkSkippedKey{
			RatchetPub: header.RatchetPub,
			N:          header.N,
		})
		adHeader, err := utils.concat(AD, *header)
		if err != nil {
			return nil, err
		}
		return utils.decrypt(*mk, ciphertext, adHeader)
	}
	return nil, nil
}

func dhRatchetReceiveChain(newState *State, header *Header) error {
	newState.Nr = 0
	newState.Dhr = &header.RatchetPub

	dhOut, err := utils.dh(newState.Dhs.Priv, *newState.Dhr)
	if err != nil {
		return err
	}

	rk, ckr, err := utils.kdfRk(newState.Rk, *dhOut)
	if err != nil {
		return err
	}
	newState.Rk = *rk
	newState.Ckr = ckr
	return nil
}

func dhRatchetSendChain(newState *State) error {
	newState.Pn = newState.Ns
	newState.Ns = 0

	dhs, err := utils.generateDH()
	if err != nil {
		return err
	}
	newState.Dhs = *dhs

	dhOut, err := utils.dh(newState.Dhs.Priv, *newState.Dhr)
	if err != nil {
		return err
	}

	rk, cks, err := utils.kdfRk(newState.Rk, *dhOut)
	if err != nil {
		return err
	}
	newState.Rk = *rk
	newState.Cks = cks
	return nil
}
