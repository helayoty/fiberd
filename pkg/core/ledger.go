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
	// ErrGrantFull: the grant's running-fiber count is at fibers.max. The
	// node never mints past the charged block — the control plane's
	// committed number is the ceiling the ledger enforces locally.
	ErrGrantFull = errors.New("ledger: grant at fibers.max, no capacity for a new fiber")
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
	fibers   map[string]fiberRef // key: fiber (handle) ID

	// perSession serializes concurrent Clone(S) on the same name — this is
	// what makes the verb idempotent under retry. At thrash-budget ceilings
	// this map is the agent's own hot lock; the fork-storm rig measures it.
	perSession sync.Map // key -> *sync.Mutex
}

type grantEntry struct {
	uid       string
	sandboxID string
	nextSeq   uint64
	fiberMax  int // <= 0 means unlimited
	live      int // running fibers, reserved at Resolve, freed at park/release
}

// fiberRef lets OnPark/OnRelease resolve a fiber ID back to the grant slot
// it occupies (and, for named sessions, the session to transition).
type fiberRef struct {
	grantUID   string
	sessionKey string // "" for anonymous fibers
}

func NewLedger(epoch uint64) *Ledger {
	return &Ledger{
		epoch:    epoch,
		grants:   make(map[string]*grantEntry),
		sessions: make(map[string]*Session),
		fibers:   make(map[string]fiberRef),
	}
}

// AdmitGrant records a grant delivered on the async lane. Its authenticated
// arrival IS the proof that admission and quota already happened; nothing is
// re-checked on the warm path. fiberMax <= 0 means unlimited — the ceiling
// is then only the grant's cgroup slice.
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
//
// Capacity is RESERVED here, not at commit: the runtime clone runs for
// milliseconds between the two, and reserving late would let a concurrent
// burst overshoot fibers.max. If the caller never commits (runtime failure,
// missed deadline), unlock returns the reservation — the caller already
// defers unlock, so abandonment cannot leak a slot.
func (l *Ledger) Resolve(grantUID, session string, tier Tier) (Action, Fence, string, func(Session), func(), error) {
	l.mu.Lock()
	g, ok := l.grants[grantUID]
	l.mu.Unlock()
	if !ok {
		return 0, Fence{}, "", nil, nil, ErrGrantUnknown
	}

	key := grantUID + "/" + session
	var sessionUnlock func()
	if session != "" {
		sm := l.lockSession(key)
		sm.Lock()
		sessionUnlock = sm.Unlock
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// reserved/committed are touched only by the caller's goroutine:
	// Resolve, then commit (on success), then the deferred unlock.
	reserved, committed := false, false

	unlock := func() {
		if reserved && !committed {
			l.mu.Lock()
			g.live--
			l.mu.Unlock()
		}
		if sessionUnlock != nil {
			sessionUnlock()
		}
	}

	mint := func() Fence {
		g.nextSeq++
		return Fence{GrantUID: grantUID, Epoch: l.epoch, Seq: g.nextSeq}
	}
	commit := func(s Session) {
		l.mu.Lock()
		defer l.mu.Unlock()
		committed = true
		if s.Handle.ID != "" {
			ref := fiberRef{grantUID: grantUID}
			if s.Name != "" {
				ref.sessionKey = key
			}
			l.fibers[s.Handle.ID] = ref
		}
		if s.Name != "" {
			l.sessions[key] = &s
		}
	}

	// reserve enforces the ceiling: the grant's fibers.max was charged at
	// admission, and the node never mints past it.
	reserve := func() error {
		if g.fiberMax > 0 && g.live >= g.fiberMax {
			return ErrGrantFull
		}
		g.live++
		reserved = true
		return nil
	}

	if session != "" {
		if s, ok := l.sessions[key]; ok {
			switch s.State {
			case StateRunning:
				// Attach returns the EXISTING fence: the incarnation did
				// not change, so neither does what credentials bind to.
				// No reservation — the fiber already holds its slot.
				return ActAttach, s.Fence, s.Handle.Endpoint, commit, unlock, nil
			case StateParked:
				if tier < TierCheckpoint {
					return 0, Fence{}, "", nil, unlock, ErrNeedsTier
				}
				if err := reserve(); err != nil {
					return 0, Fence{}, "", nil, unlock, err
				}
				return ActResume, mint(), s.DeltaRef, commit, unlock, nil
			}
		}
	}
	if err := reserve(); err != nil {
		return 0, Fence{}, "", nil, unlock, err
	}
	return ActCreate, mint(), "", commit, unlock, nil
}

// OnPark records a successful runtime Park: the fiber leaves the running
// tier (freeing its fibers.max slot) and, for a named session, the delta
// ref is kept so a later Clone(S) resolves to ActResume.
func (l *Ledger) OnPark(fiberID, deltaRef string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return
	}
	delete(l.fibers, fiberID)
	if g, ok := l.grants[ref.grantUID]; ok {
		g.live--
	}
	if ref.sessionKey != "" {
		if s, ok := l.sessions[ref.sessionKey]; ok {
			s.State = StateParked
			s.DeltaRef = deltaRef
			s.Handle = FiberHandle{}
		}
	}
}

// OnRelease records a successful runtime Release: the slot is freed and the
// session name, if any, is forgotten.
func (l *Ledger) OnRelease(fiberID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return
	}
	delete(l.fibers, fiberID)
	if g, ok := l.grants[ref.grantUID]; ok {
		g.live--
	}
	if ref.sessionKey != "" {
		delete(l.sessions, ref.sessionKey)
	}
}
