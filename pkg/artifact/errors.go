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

// ErrEntryName means an images archive names an entry that is not a
// plain file name, as TarDir writes them.
var ErrEntryName = errors.New("artifact: archive entry is not a plain file name")
