package doubleratchet

import (
	"minimal-signal/crypto/key_ed25519"
)

const (
	// maxSkip is the constant specifying the maximum number of message keys that can be skipped in a single chain
	maxSkip = 1000 // TODO: this is a random value
)

type DoubleRatchet interface {
	// Encrypt is the exported function that performs a symmetric-key ratchet step, then encrypts the message with the
	// resulting message key. In addition to the message’s plaintext it takes an AD byte sequence which is prepended
	// to the header to form the associated data for the underlying AEAD encryption.
	Encrypt(plaintext []byte, associatedData []byte) (header *Header, ciphertext []byte, err error)

	// Decrypt is the exported function that decrypts messages. It does the following:
	// • If the message corresponds to a skipped message key this function decrypts the message,
	// deletes the message key, and returns.
	// • Otherwise, if a new ratchet key has been received this function stores any skipped message keys from the
	// receiving chain and performs a DH ratchet step to replace the sending and receiving chains.
	// • This function then stores any skipped message keys from the current receiving chain, performs a symmetric-key
	// ratchet step to derive the relevant message key and next chain key, and decrypts the message.
	// If an exception is raised (e.g. message authentication failure) then the message is discarded and changes to
	// the state object are discarded. Otherwise, accept the decrypted plaintext and store changes to the state object.
	Decrypt(header Header, ciphertext []byte, associatedData []byte) (plaintext []byte, err error)

	// MaxSkip returns the constant specifying the maximum number of message keys that can be skipped in a single chain
	MaxSkip() MsgIndex
}

// doubleRatchetImpl implements the DoubleRatchet interface.
// https://signal.org/docs/specifications/doubleratchet/#encrypting-messages and
// https://signal.org/docs/specifications/doubleratchet/#decrypting-messages
type doubleRatchetImpl struct {
	currentState *state
	utils        doubleRatchetUtils
}

func NewDoubleRatchet(initState *state) DoubleRatchet {
	if initState.mkSkipped == nil {
		initState.mkSkipped = make(map[mkSkippedKey]*MsgKey)
	}
	return &doubleRatchetImpl{
		currentState: initState,
		utils:        newDoubleRatchetUtils(),
	}
}

// InitAlice initializes the Double Ratchet for the sender
func InitAlice(sk RatchetKey, bobDHPubKey key_ed25519.PublicKey) (DoubleRatchet, error) {
	utils := newDoubleRatchetUtils()

	// Init dhs
	dhs, err := utils.generateDH()
	if err != nil {
		return nil, err
	}

	// Init dhr
	dhr := bobDHPubKey

	// Init rk, cks
	kdfRkInput, err := utils.dh(dhs.Priv, dhr)
	if err != nil {
		return nil, err
	}
	rk, cks, err := utils.kdfRk(sk, *kdfRkInput)
	if err != nil {
		return nil, err
	}

	return NewDoubleRatchet(&state{
		dhs: *dhs,
		dhr: &dhr,
		rk:  *rk,
		cks: cks,
		// ckr, ns, nr, pn, mkSkipped are init as zero values
	}), nil
}

// InitBob initializes the Double Ratchet for the receiver
func InitBob(sk RatchetKey, bobDHKeyPair key_ed25519.Pair) DoubleRatchet {
	return NewDoubleRatchet(&state{
		dhs: bobDHKeyPair,
		rk:  sk,
		// dhr, cks, ckr, ns, nr, pn, mkSkipped are init as zero values
	})
}

func (dr *doubleRatchetImpl) Encrypt(plaintext []byte, associatedData []byte) (*Header, []byte, error) {
	var (
		mk  *MsgKey
		err error
	)

	// 1. Generate current message key & update chain key
	dr.currentState.cks, mk, err = dr.utils.kdfCk(*dr.currentState.cks)
	if err != nil {
		return nil, nil, err
	}

	// 2. Create header & its byte sequence
	header := Header{
		RatchetPub: dr.currentState.dhs.Pub,
		Pn:         dr.currentState.pn,
		N:          dr.currentState.ns,
	}

	// 3. Update state.ns
	dr.currentState.ns++

	// 4. Encrypt plaintext w/ header + associatedData
	ad, err := dr.utils.concat(associatedData, header)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := dr.utils.encrypt(*mk, plaintext, ad)
	if err != nil {
		return nil, nil, err
	}

	return &header, ciphertext, nil
}

func (dr *doubleRatchetImpl) Decrypt(header Header, ciphertext []byte, associatedData []byte) ([]byte, error) {
	var (
		// If no error occurs, dr.currentState will be updated with newState
		newState = *dr.currentState
		mk       *MsgKey
	)
	// 1. Try to decrypt with skipped message keys
	plaintext, err := dr.trySkippedMessageKeys(&newState, &header, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}
	if plaintext != nil {
		return plaintext, nil
	}

	// 2. If a new ratchet key has been received, save skipped message keys from the receiving chain and
	// perform a DH ratchet step
	if header.RatchetPub != *newState.dhr {
		// If a new ratchet key has been received
		if err := dr.skipMessageKeys(&newState, header.Pn); err != nil {
			return nil, err
		}
		if err := dr.dhRatchet(&newState, &header); err != nil {
			return nil, err
		}
	}

	// 3. Store skipped message keys from the current receiving chain if needed
	if err := dr.skipMessageKeys(&newState, header.N); err != nil {
		return nil, err
	}

	// 4. Get message key
	newState.ckr, mk, err = dr.utils.kdfCk(*newState.ckr)
	if err != nil {
		return nil, err
	}
	newState.nr++

	// 5. Update state
	dr.currentState = &newState

	// 6. Decrypt
	adHeader, err := dr.utils.concat(associatedData, header)
	if err != nil {
		return nil, err
	}
	return dr.utils.decrypt(*mk, ciphertext, adHeader)
}

func (dr *doubleRatchetImpl) MaxSkip() MsgIndex {
	return maxSkip
}

func (dr *doubleRatchetImpl) trySkippedMessageKeys(newState *state, header *Header, ciphertext, AD []byte) ([]byte, error) {
	if mk, exists := newState.mkSkipped[mkSkippedKey{
		RatchetPub: header.RatchetPub,
		N:          header.N,
	}]; exists {
		delete(newState.mkSkipped, mkSkippedKey{
			RatchetPub: header.RatchetPub,
			N:          header.N,
		})
		adHeader, err := dr.utils.concat(AD, *header)
		if err != nil {
			return nil, err
		}
		return dr.utils.decrypt(*mk, ciphertext, adHeader)
	}
	return nil, nil
}

func (dr *doubleRatchetImpl) skipMessageKeys(newState *state, until MsgIndex) error {
	if newState.nr+dr.MaxSkip() < until {
		return ErrSkippingTooManyKeys
	}

	if newState.ckr != nil {
		for newState.nr < until {
			var mk *MsgKey
			var err error
			newState.ckr, mk, err = dr.utils.kdfCk(*newState.ckr)
			if err != nil {
				return err
			}
			newState.mkSkipped[mkSkippedKey{
				RatchetPub: *newState.dhr,
				N:          newState.nr,
			}] = mk
			newState.nr++
		}
	}
	return nil
}

func (dr *doubleRatchetImpl) dhRatchet(newState *state, header *Header) error {
	newState.pn = newState.ns
	newState.ns = 0
	newState.nr = 0
	newState.dhr = &header.RatchetPub

	dhOut, err := dr.utils.dh(newState.dhs.Priv, *newState.dhr)
	if err != nil {
		return err
	}

	rk, ckr, err := dr.utils.kdfRk(newState.rk, *dhOut)
	if err != nil {
		return err
	}
	newState.rk = *rk
	newState.ckr = ckr

	dhs, err := dr.utils.generateDH()
	if err != nil {
		return err
	}
	newState.dhs = *dhs

	dhOut, err = dr.utils.dh(newState.dhs.Priv, *newState.dhr)
	if err != nil {
		return err
	}

	rk, cks, err := dr.utils.kdfRk(newState.rk, *dhOut)
	if err != nil {
		return err
	}
	newState.rk = *rk
	newState.cks = cks
	return nil
}
