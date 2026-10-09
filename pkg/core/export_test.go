package core

import "os"

// SwapSpoolFile replaces the file a spool writes to and returns the old
// one, so a test can make writes fail.
func SwapSpoolFile(s *Spool, f *os.File) *os.File {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.f
	s.f = f
	return old
}

// SetSpoolFsync replaces what a spool calls to make the file durable, so a
// test can count fsyncs, hold one in flight, or make one fail.
func SetSpoolFsync(s *Spool, fn func(*os.File) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fsync = fn
}

// Subscribe registers a Watch wake-up channel, so a test can see which
// transitions notify.
func Subscribe(a *Agent) chan struct{} { return a.subscribe() }

// SetExitLookedUp installs what OnExit calls once it has looked the fiber
// up, with whether the ledger knew it, so a test can order an exit
// against a commit.
func SetExitLookedUp(a *Agent, fn func(fiberID string, known bool)) { a.exitLookedUp = fn }

// Seq returns a spool's last assigned sequence number.
func (s *Spool) Seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Resolve is resolveHeld with the session's hold taken first, as Clone
// takes it.
func (l *Ledger) Resolve(grantUID, session string, tier Tier) (Action, Fence, string, func(Session) bool, func(), error) {
	l.mu.Lock()
	_, ok := l.grants[grantUID]
	l.mu.Unlock()
	if !ok {
		return 0, Fence{}, "", nil, nil, ErrGrantUnknown
	}
	var hold *sessionHold
	if session != "" {
		hold = l.holdSession(grantUID, session)
	}
	return l.resolveHeld(hold, grantUID, session, tier)
}

// SessionGates is how many per-session gates the ledger holds right now.
func SessionGates(l *Ledger) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.perSession)
}
