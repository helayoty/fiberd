package core

import (
	"errors"
	"sync"
	"time"
)

// SessionState is the ladder: it is the same triple as the density budget.
type SessionState int

const (
	StateRunning SessionState = iota // running tier: cgroup, fds, address
	StateParked                      // activatable tier: delta on disk
)

// Session couples a stable identity (Name — what "my worker" refers to)
// with a mutable incarnation (Fence — what credentials and claims bind to).
// The name survives incarnations; nothing else does.
type Session struct {
	Name     string
	GrantUID string
	State    SessionState
	Fence    Fence
	Handle   FiberHandle // valid when StateRunning
	DeltaRef string      // valid when StateParked
	LeaseEnd time.Time
}

// Action is the resolved outcome of Clone(S): one verb, three costs.
type Action int

const (
	ActAttach Action = iota // S running: return existing endpoint, ~free
	ActResume               // S parked: restore delta, sub-second
	ActCreate               // S unknown (or anonymous): fork zygote, ms
)

var (
	ErrGrantUnknown = errors.New("ledger: grant not held by this node")
	ErrNeedsTier    = errors.New("ledger: parked session but runtime lacks TierCheckpoint")
)

// Ledger is the node-authoritative record of grants and sessions. It is a
// cache of reality: authoritative state is rebuilt at startup from
// Runtime.List reconciled against the on-disk snapshot, and discrepancies
// resolve in favor of what is actually running.
type Ledger struct {
	epoch uint64

	mu       sync.Mutex
	grants   map[string]*grantEntry
	sessions map[string]*Session // key: grantUID + "/" + name

	// perSession serializes concurrent Clone(S) on the same name — this is
	// what makes the verb idempotent under retry. At thrash-budget ceilings
	// this map is the agent's own hot lock; the fork-storm rig measures it.
	perSession sync.Map // key -> *sync.Mutex
}

type grantEntry struct {
	uid       string
	sandboxID string
	nextSeq   uint64
	fiberMax  int
	live      int
}

func NewLedger(epoch uint64) *Ledger {
	return &Ledger{
		epoch:    epoch,
		grants:   make(map[string]*grantEntry),
		sessions: make(map[string]*Session),
	}
}

// AdmitGrant records a grant delivered on the async lane. Its authenticated
// arrival IS the proof that admission and quota already happened; nothing is
// re-checked on the warm path.
func (l *Ledger) AdmitGrant(uid, sandboxID string, fiberMax int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.grants[uid] = &grantEntry{uid: uid, sandboxID: sandboxID, fiberMax: fiberMax}
}

func (l *Ledger) RevokeGrant(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.grants, uid)
	// Fibers under a revoked grant drain by lease non-renewal; revocation
	// latency during a control-plane outage is bounded by lease TTL.
}

// lockSession returns the per-name mutex, creating it on first use.
func (l *Ledger) lockSession(key string) *sync.Mutex {
	m, _ := l.perSession.LoadOrStore(key, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// Resolve decides which of the three paths Clone takes and mints the fence
// for it. The caller performs the runtime work and then Commit()s; holding
// the per-session lock across both is what forbids duplicate sessions.
func (l *Ledger) Resolve(grantUID, session string, tier Tier) (Action, Fence, string, func(Session), func(), error) {
	l.mu.Lock()
	g, ok := l.grants[grantUID]
	l.mu.Unlock()
	if !ok {
		return 0, Fence{}, "", nil, nil, ErrGrantUnknown
	}

	key := grantUID + "/" + session
	var unlock func()
	if session != "" {
		sm := l.lockSession(key)
		sm.Lock()
		unlock = sm.Unlock
	} else {
		unlock = func() {}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	mint := func() Fence {
		g.nextSeq++
		return Fence{GrantUID: grantUID, Epoch: l.epoch, Seq: g.nextSeq}
	}
	commit := func(s Session) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if s.State == StateRunning {
			g.live++
		}
		if s.Name != "" {
			l.sessions[key] = &s
		}
	}

	if session != "" {
		if s, ok := l.sessions[key]; ok {
			switch s.State {
			case StateRunning:
				// Attach returns the EXISTING fence: the incarnation did
				// not change, so neither does what credentials bind to.
				return ActAttach, s.Fence, s.Handle.Endpoint, commit, unlock, nil
			case StateParked:
				if tier < TierCheckpoint {
					return 0, Fence{}, "", nil, unlock, ErrNeedsTier
				}
				return ActResume, mint(), s.DeltaRef, commit, unlock, nil
			}
		}
	}
	return ActCreate, mint(), "", commit, unlock, nil
}
