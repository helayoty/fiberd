package core

import (
	"errors"
	"sort"
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
}

// Action is the resolved outcome of Clone(S): one verb, three costs.
type Action int

const (
	ActCreate Action = iota // S unknown (or anonymous): fork zygote, ms
	ActAttach               // S running: return existing endpoint, ~free
	ActResume               // S parked: restore delta, sub-second
)

func (a Action) String() string {
	switch a {
	case ActAttach:
		return "attach"
	case ActResume:
		return "resume"
	default:
		return "create"
	}
}

var (
	ErrGrantUnknown = errors.New("ledger: grant not held by this home")
	// ErrGrantExpired: the lease lapsed. Revocation is lease non-renewal,
	// so this is capacity the home no longer holds, not an auth failure.
	ErrGrantExpired = errors.New("ledger: grant lease expired")
	// ErrNeedsTier: the runtime's tier is below what the grant demands
	// (min_tier) or what the session needs (a parked delta requires
	// TierCheckpoint). Never satisfied by a lesser mechanism.
	ErrNeedsTier = errors.New("ledger: runtime tier below what the grant or session requires")
	// ErrGrantFull: the grant's running-fiber count is at fibers.max. The
	// home never mints past the charged block.
	ErrGrantFull = errors.New("ledger: grant at fibers.max, no capacity for a new fiber")
	// ErrFiberUnknown: no running fiber by that ID in this epoch. Every
	// fiber from before a restart is unknown by construction.
	ErrFiberUnknown = errors.New("ledger: fiber unknown in this epoch")
)

// Status is the batched, per-grant view a home publishes. It is the only
// thing a control plane ever sees; never individual fibers.
type Status struct {
	GrantUID   string
	Running    int
	Parked     int
	WUsedBytes uint64
	Latest     Fence // the most recently minted fence for the grant
}

// Ledger is the home-authoritative record of grants and sessions. It is a
// cache of reality: at startup it is rebuilt from Runtime.List reconciled
// against the on-disk snapshot, and discrepancies resolve in favor of what
// is actually running (Phase 3.5 wires the snapshot).
type Ledger struct {
	epoch uint64

	// Now is the clock used for lease expiry. Tests inject it.
	Now func() time.Time

	mu       sync.Mutex
	grants   map[string]*grantEntry
	sessions map[string]*Session  // key: grantUID + "/" + name
	fibers   map[string]*fiberRef // key: fiber (handle) ID

	// perSession serializes concurrent Clone(S) on the same name — this is
	// what makes the verb idempotent under retry. Entries are refcounted
	// and deleted when the last in-flight Resolve drops them, so the map is
	// bounded by concurrency, not by session names ever seen.
	perSession map[string]*sessionGate
}

type sessionGate struct {
	mu   sync.Mutex
	refs int
}

type grantEntry struct {
	grant   Grant
	nextSeq uint64
	live    int // running fibers, reserved at Resolve, freed at park/release/exit
}

// fiberRef lets park/release/exit resolve a fiber ID back to the grant
// slot it occupies and, for named sessions, the session to transition.
type fiberRef struct {
	grantUID   string
	sessionKey string // "" for anonymous fibers
	fence      Fence
	wUsed      uint64
}

func NewLedger(epoch uint64) *Ledger {
	return &Ledger{
		epoch:      epoch,
		Now:        time.Now,
		grants:     make(map[string]*grantEntry),
		sessions:   make(map[string]*Session),
		fibers:     make(map[string]*fiberRef),
		perSession: make(map[string]*sessionGate),
	}
}

func (l *Ledger) Epoch() uint64 { return l.epoch }

// AdmitGrant records a verified grant. Its authenticated arrival IS the
// proof that admission and quota already happened; nothing is re-checked
// on the warm path. Idempotent on the UID: a re-delivery refreshes the
// mutable fields in place and never resets nextSeq (fences would be
// reminted) or live (the ceiling would be corrupted).
func (l *Ledger) AdmitGrant(g Grant) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.grants[g.UID]; ok {
		e.grant = g
		return
	}
	l.grants[g.UID] = &grantEntry{grant: g}
}

// Grant returns the admitted grant, if any.
func (l *Ledger) Grant(uid string) (Grant, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.grants[uid]
	if !ok {
		return Grant{}, false
	}
	return e.grant, true
}

// RevokeGrant drops the grant. Fibers under it drain by lease
// non-renewal; the reaper (Phase 3.5) tears them down.
func (l *Ledger) RevokeGrant(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.grants, uid)
}

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
// for it. The caller performs the runtime work and then commits; holding
// the per-session lock across both is what forbids duplicate sessions.
//
// Capacity is RESERVED here, not at commit: the runtime clone runs for
// milliseconds between the two, and reserving late would let a concurrent
// burst overshoot fibers.max. If the caller never commits, unlock returns
// the reservation.
//
// tier is the runtime's advertised tier. A grant whose min_tier exceeds it,
// or a parked session on a sub-checkpoint runtime, is ErrNeedsTier: never
// a fresh fork.
func (l *Ledger) Resolve(grantUID, session string, tier Tier) (Action, Fence, string, func(Session), func(), error) {
	l.mu.Lock()
	_, ok := l.grants[grantUID]
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

	unlockNoReserve := func() {
		if sessionUnlock != nil {
			sessionUnlock()
		}
	}

	// Re-check under the lock we now hold: the grant may have been revoked
	// while we waited on the session mutex.
	g, ok := l.grants[grantUID]
	if !ok {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrGrantUnknown
	}
	if g.grant.Expired(l.Now()) {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrGrantExpired
	}
	if g.grant.MinTier > tier {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrNeedsTier
	}

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
			ref := &fiberRef{grantUID: grantUID, fence: s.Fence}
			if s.Name != "" {
				ref.sessionKey = key
			}
			l.fibers[s.Handle.ID] = ref
		}
		if s.Name != "" {
			l.sessions[key] = &s
		}
	}

	reserve := func() error {
		if g.grant.FiberMax > 0 && g.live >= g.grant.FiberMax {
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

// SessionState reports a named session's state, if the ledger knows it.
func (l *Ledger) SessionState(grantUID, session string) (SessionState, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[grantUID+"/"+session]
	if !ok {
		return 0, "", false
	}
	return s.State, s.DeltaRef, true
}

// ForgetSession drops a parked session (its delta was claimed elsewhere).
func (l *Ledger) ForgetSession(grantUID, session string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.sessions[grantUID+"/"+session]; ok && s.State == StateParked {
		delete(l.sessions, grantUID+"/"+session)
	}
}

// Fiber returns the fence of a running fiber, or false if the ID is not
// known in this epoch.
func (l *Ledger) Fiber(fiberID string) (Fence, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return Fence{}, false
	}
	return ref.fence, true
}

// FibersOf lists the running fibers of one grant with their session name
// and last sampled W, for the pressure ladder.
func (l *Ledger) FibersOf(grantUID string) []FiberInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []FiberInfo
	for id, ref := range l.fibers {
		if ref.grantUID != grantUID {
			continue
		}
		fi := FiberInfo{ID: id, WUsed: ref.wUsed}
		if ref.sessionKey != "" {
			if s, ok := l.sessions[ref.sessionKey]; ok {
				fi.Session = s.Name
			}
		}
		out = append(out, fi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RunningFibers lists the IDs of every running fiber, for the sampler.
func (l *Ledger) RunningFibers() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := make([]string, 0, len(l.fibers))
	for id := range l.fibers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// SetFiberW records the latest dirtied-working-set measurement.
func (l *Ledger) SetFiberW(fiberID string, bytes uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ref, ok := l.fibers[fiberID]; ok {
		ref.wUsed = bytes
	}
}

// OnPark records a successful runtime Park: the fiber leaves the running
// tier (freeing its slot) and, for a named session, the delta ref is kept
// so a later Clone(S) resolves to ActResume. Returns the session name
// ("" for an anonymous fiber, whose delta nobody can ask for).
func (l *Ledger) OnPark(fiberID, deltaRef string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return ""
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
			return s.Name
		}
	}
	return ""
}

// OnRelease records a successful runtime Release: the slot is freed and
// the session name, if any, is forgotten.
func (l *Ledger) OnRelease(fiberID string) {
	l.onGone(fiberID)
}

// OnFiberExit records a fiber that died on its own (OOM, exit, signal).
// The slot is freed and a named session is forgotten: its state is gone,
// and pretending it is parked would resume nothing. Returns the fence the
// fiber held and the session name, for the audit record.
func (l *Ledger) OnFiberExit(fiberID string) (Fence, string, bool) {
	return l.onGone(fiberID)
}

func (l *Ledger) onGone(fiberID string) (Fence, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return Fence{}, "", false
	}
	delete(l.fibers, fiberID)
	if g, ok := l.grants[ref.grantUID]; ok {
		g.live--
	}
	var name string
	if ref.sessionKey != "" {
		if s, ok := l.sessions[ref.sessionKey]; ok {
			name = s.Name
		}
		delete(l.sessions, ref.sessionKey)
	}
	return ref.fence, name, true
}

// Status computes the batched view for one grant.
func (l *Ledger) Status(uid string) (Status, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.grants[uid]
	if !ok {
		return Status{}, false
	}
	return l.statusLocked(uid, e), true
}

// Statuses computes the view for every admitted grant, sorted by UID.
func (l *Ledger) Statuses() []Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Status, 0, len(l.grants))
	for uid, e := range l.grants {
		out = append(out, l.statusLocked(uid, e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantUID < out[j].GrantUID })
	return out
}

func (l *Ledger) statusLocked(uid string, e *grantEntry) Status {
	st := Status{GrantUID: uid, Running: e.live,
		Latest: Fence{GrantUID: uid, Epoch: l.epoch, Seq: e.nextSeq}}
	for _, ref := range l.fibers {
		if ref.grantUID == uid {
			st.WUsedBytes += ref.wUsed
		}
	}
	for _, s := range l.sessions {
		if s.GrantUID == uid && s.State == StateParked {
			st.Parked++
		}
	}
	return st
}
