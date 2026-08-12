package core

import (
	"errors"
	"sync"
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
//
// TODO(poc): the startup rebuild described above does not exist yet. The
// Ledger has no snapshot load/save path and NewLedger returns empty maps, so
// a restart loses every grant/session/fiber and cannot reconcile against
// running instances. Add Snapshot()/Restore() (or equivalent) here and wire
// them to the reconcile in cmd/fiberd/main.go.
type Ledger struct {
	epoch uint64

	mu       sync.Mutex
	grants   map[string]*grantEntry
	sessions map[string]*Session // key: grantUID + "/" + name
	fibers   map[string]fiberRef // key: fiber (handle) ID

	// perSession serializes concurrent Clone(S) on the same name — this is
	// what makes the verb idempotent under retry. At thrash-budget ceilings
	// this map is the agent's own hot lock; the fork-storm rig measures it.
	// Guarded by mu. Entries are refcounted and deleted when the last
	// in-flight Resolve drops them, so the map is bounded by concurrency,
	// not by the number of distinct session names ever seen.
	perSession map[string]*sessionGate
}

// sessionGate is the per-name serialization lock plus a refcount that keeps
// the map entry alive exactly while it is in use. refs is guarded by mu.
type sessionGate struct {
	mu   sync.Mutex
	refs int
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
		epoch:      epoch,
		grants:     make(map[string]*grantEntry),
		sessions:   make(map[string]*Session),
		fibers:     make(map[string]fiberRef),
		perSession: make(map[string]*sessionGate),
	}
}

// AdmitGrant records a grant delivered on the async lane. Its authenticated
// arrival IS the proof that admission and quota already happened; nothing is
// re-checked on the warm path. fiberMax <= 0 means unlimited — the ceiling
// is then only the grant's cgroup slice.
func (l *Ledger) AdmitGrant(uid, sandboxID string, fiberMax int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Idempotent on the grant UID: a re-delivery (informer relist, reconnect,
	// duplicate event) must NOT reset the entry. Overwriting it would zero
	// nextSeq — reminting fences that were already handed out, so an incarnation
	// could reuse a fence — and zero live, corrupting the fibers.max ceiling
	// against the fibers still running. On re-admit we only refresh the mutable
	// delivery fields (sandboxID, fiberMax) in place.
	if g, ok := l.grants[uid]; ok {
		g.sandboxID = sandboxID
		g.fiberMax = fiberMax
		return
	}
	l.grants[uid] = &grantEntry{uid: uid, sandboxID: sandboxID, fiberMax: fiberMax}
	// TODO(poc): the warm floor (adapter.Grant.WarmCount / fibers.warm) is not
	// admitted here — AdmitGrant only takes fiberMax. grantEntry has no warm
	// target and nothing pre-forks or backfills warm fibers. Accept the warm
	// count, store it on grantEntry, and drive a backfill.
}

func (l *Ledger) RevokeGrant(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.grants, uid)
	// Fibers under a revoked grant drain by lease non-renewal; revocation
	// latency during a control-plane outage is bounded by lease TTL.
	//
	// TODO(poc): the lease + reaper described above is not implemented. Today
	// RevokeGrant only drops the grantEntry; the fibers and sessions it owned
	// remain in l.fibers/l.sessions and their runtime instances keep running.
	// Implement per-grant leases with TTL-bounded renewal and a background
	// reaper that, on non-renewal or revoke, tears down the grant's live
	// fibers (Runtime teardown) and purges their ledger entries.
}

// acquireSession takes the per-name lock, creating its gate on first use and
// counting this caller so the entry cannot be reclaimed while in flight. The
// returned gate holds its mutex; the caller MUST pass it to releaseSession
// exactly once. Refcounting under mu is what makes cleanup safe: the entry is
// deleted only when no Resolve references it, so two callers for the same key
// can never end up on different mutexes.
func (l *Ledger) acquireSession(key string) *sessionGate {
	l.mu.Lock()
	gate := l.perSession[key]
	if gate == nil {
		gate = &sessionGate{}
		l.perSession[key] = gate
	}
	gate.refs++
	l.mu.Unlock()
	gate.mu.Lock()
	return gate
}

// releaseSession drops the per-name lock and the caller's reference, deleting
// the gate when it was the last one out. Order matters: unlock the gate first,
// then take mu — never hold gate.mu while acquiring mu.
func (l *Ledger) releaseSession(key string, gate *sessionGate) {
	gate.mu.Unlock()
	l.mu.Lock()
	gate.refs--
	if gate.refs == 0 {
		delete(l.perSession, key)
	}
	l.mu.Unlock()
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
		gate := l.acquireSession(key)
		sessionUnlock = func() { l.releaseSession(key, gate) }
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Re-check under the lock we now hold: the grant may have been revoked
	// while we waited on the session mutex. A stale *grantEntry would mint
	// fences and reserve slots against capacity the node no longer holds.
	g, ok = l.grants[grantUID]
	if !ok {
		unlock := func() {
			if sessionUnlock != nil {
				sessionUnlock()
			}
		}
		return 0, Fence{}, "", nil, unlock, ErrGrantUnknown
	}

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
