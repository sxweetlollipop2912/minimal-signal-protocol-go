package doubleratchet

import "errors"

var (
	ErrInvalidSecretLength = errors.New("invalid secret length")
	ErrInvalidTag          = errors.New("invalid tag")
)
