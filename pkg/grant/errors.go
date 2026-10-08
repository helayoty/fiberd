package grant

import (
	"errors"
	"fmt"
)

// Token errors.
var (
	ErrNoKID          = errors.New("grant: token has no kid header")
	ErrClaimMismatch  = errors.New("grant: registered claims disagree with the grant claim")
	ErrWrongAudience  = errors.New("grant: audience mismatch")
	ErrWrongIssuer    = errors.New("grant: issuer mismatch")
	ErrMissingGrant   = errors.New("grant: token carries no grant claim")
	ErrKeyMismatchAlg = errors.New("grant: key algorithm does not match token")
	ErrTokenTooLarge  = fmt.Errorf("grant: token exceeds %d bytes", MaxTokenBytes)
	ErrLeaseTooLong   = errors.New("grant: lease longer than this home accepts")
	ErrEmptyGrant     = errors.New("grant: grant_uid is empty")
	ErrBadUID         = errors.New("grant: grant_uid must be a DNS-1123 label (lowercase alphanumerics and '-', at most 63)")
)

// Key set errors.
var (
	ErrUnknownKey  = errors.New("grant: no key for kid")
	ErrNeverLoaded = errors.New("grant: key set never loaded")
	ErrJWKSStale   = errors.New("grant: key set older than the lease TTL")
)
