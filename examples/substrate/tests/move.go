package substratetest

import (
	"fmt"
	"time"
)

// moveLine is one side of Run E's move in one line, the record
// docs/benchmarks.md copies. The fiberd side is a restore on another
// worker. The plain side is the same counter started there as a plain
// process, which has no actor and no snapshot ("-").
func moveLine(side, backend, actor, from, to string, ready time.Duration, count string, kept bool) string {
	state := "lost"
	if kept {
		state = "kept"
	}
	return fmt.Sprintf("move: side=%s backend=%s actor=%s from=%s to=%s ready=%s count=%s state=%s",
		side, backend, actor, from, to, ready.Round(time.Millisecond), count, state)
}
