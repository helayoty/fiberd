package consumer

import "errors"

// ErrNotHandoff means the fiber was not cloned under a HANDOFF grant, so
// it has no routing key. Dial its Endpoint directly.
var ErrNotHandoff = errors.New("consumer: not a handoff fiber")
