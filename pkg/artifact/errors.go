package artifact

import "errors"

// ErrUntrusted means a directory artifact is unsigned, signed by a key
// the home does not trust, or signed over content it no longer holds.
var ErrUntrusted = errors.New("artifact: not signed by a trusted key")

// ErrSealed means a sealed file does not open with this home's key for
// the domain and session asked for, or it was changed after sealing.
var ErrSealed = errors.New("artifact: sealed content does not open")

// ErrExpired means a sealed delta is past the expiry it was sealed with.
var ErrExpired = errors.New("artifact: sealed content has expired")
