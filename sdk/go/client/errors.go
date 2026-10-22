package client

import "errors"

// ErrNotHandoff means the fiber was not cloned under a HANDOFF grant, so
// it has no routing key. Dial its Endpoint directly.
var ErrNotHandoff = errors.New("client: not a handoff fiber")

// ErrSize means an upload's reader does not hold the size it declared,
// or the size is negative. fiberd never placed the file.
var ErrSize = errors.New("client: the upload's reader does not match its size")

// errEndedEarly is fiberd answering an upload before it took every byte.
// fiberd never does that.
var errEndedEarly = errors.New("client: fiberd ended the upload before its last byte")
