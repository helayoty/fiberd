package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Snapshot is the on-disk cache of the ledger. It is a cache: at boot the
// runtime's view of reality wins, and the snapshot only tells the agent
// which grants to re-admit and which parked sessions to remember.
type Snapshot struct {
	Epoch    uint64            `json:"epoch"`
	SavedAt  time.Time         `json:"saved_at"`
	Grants   []Grant           `json:"grants"`
	Sessions []SessionSnapshot `json:"sessions"`
	Fibers   []FiberSnapshot   `json:"fibers"`
}

type SessionSnapshot struct {
	Name     string       `json:"name"`
	GrantUID string       `json:"grant_uid"`
	State    SessionState `json:"state"`
	Fence    Fence        `json:"fence"`
	DeltaRef string       `json:"delta_ref,omitempty"`
	FiberID  string       `json:"fiber_id,omitempty"`
}

type FiberSnapshot struct {
	ID       string `json:"id"`
	GrantUID string `json:"grant_uid"`
	Session  string `json:"session,omitempty"`
	Fence    Fence  `json:"fence"`
}

// Snapshot captures the ledger.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Snapshot{Epoch: l.epoch, SavedAt: l.Now()}
	for _, e := range l.grants {
		s.Grants = append(s.Grants, e.grant)
	}
	for _, sess := range l.sessions {
		ss := SessionSnapshot{Name: sess.Name, GrantUID: sess.GrantUID, State: sess.State, Fence: sess.Fence, DeltaRef: sess.DeltaRef}
		if sess.State == StateRunning {
			ss.FiberID = sess.Handle.ID
		}
		s.Sessions = append(s.Sessions, ss)
	}
	for id, ref := range l.fibers {
		fs := FiberSnapshot{ID: id, GrantUID: ref.grantUID, Fence: ref.fence}
		if ref.sessionKey != "" {
			if sess, ok := l.sessions[ref.sessionKey]; ok {
				fs.Session = sess.Name
			}
		}
		s.Fibers = append(s.Fibers, fs)
	}
	return s
}

// RestoreParked re-registers a parked session from a snapshot. Its fence
// is the one it was parked under (an older epoch): resume mints a new
// one, so the old value only documents lineage.
func (l *Ledger) RestoreParked(s SessionSnapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.grants[s.GrantUID]; !ok {
		return
	}
	key := s.GrantUID + "/" + s.Name
	l.sessions[key] = &Session{Name: s.Name, GrantUID: s.GrantUID, State: StateParked, Fence: s.Fence, DeltaRef: s.DeltaRef}
}

// SnapshotStore persists snapshots atomically at Path (tmp + rename).
type SnapshotStore struct{ Path string }

func (st SnapshotStore) Save(s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.Path)
}

// Load returns the snapshot, or an empty one when none exists.
func (st SnapshotStore) Load() (Snapshot, error) {
	b, err := os.ReadFile(st.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		// A torn snapshot is a cache miss, not a fatal error: reality is
		// rebuilt from the runtime; only parked sessions are forgotten.
		log.Printf("snapshot: %s unreadable (%v); treating as empty", filepath.Base(st.Path), err)
		return Snapshot{}, nil
	}
	return s, nil
}

// DeltaChecker is implemented by runtimes that can say whether a parked
// delta ref still exists. Without it, parked sessions are restored from
// the snapshot on trust.
type DeltaChecker interface {
	HasDelta(ref string) bool
}

// ReconcileReport says what boot found.
type ReconcileReport struct {
	GrantsReadmitted int
	GrantsExpired    int
	ParkedRestored   int
	ParkedDropped    int
	OrphansKilled    int
}

// Reconcile is the boot step between epoch++ and opening the warm path:
//
//  1. every unexpired grant in the snapshot is re-admitted (its template
//     warmed again: the previous zygote died with the previous agent);
//  2. every parked session whose delta still exists is remembered, so a
//     Clone(S) after restart resumes it under the new epoch;
//  3. every fiber the runtime still reports is from a prior epoch by
//     construction and is killed: its fence is invalid, and nothing
//     minted before the restart validates after it.
//
// Reality wins over the snapshot at every step.
func (a *Agent) Reconcile(ctx context.Context, snap Snapshot) (ReconcileReport, error) {
	var rep ReconcileReport
	now := a.Ledger.Now()
	for _, g := range snap.Grants {
		if g.Expired(now) {
			rep.GrantsExpired++
			_ = a.audit(ctx, BestEffort, AuditRecord{Event: "expire", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Detail: "at boot"})
			continue
		}
		if _, err := a.Admit(ctx, g); err != nil {
			log.Printf("reconcile: re-admit %s: %v", g.UID, err)
			continue
		}
		rep.GrantsReadmitted++
	}
	checker, canCheck := a.Runtime.(DeltaChecker)
	for _, s := range snap.Sessions {
		if s.State != StateParked || s.DeltaRef == "" {
			continue
		}
		if canCheck && !checker.HasDelta(s.DeltaRef) {
			rep.ParkedDropped++
			continue
		}
		if _, ok := a.Ledger.Grant(s.GrantUID); !ok {
			rep.ParkedDropped++
			continue
		}
		a.Ledger.RestoreParked(s)
		rep.ParkedRestored++
	}
	running, err := a.Runtime.List(ctx)
	if err != nil {
		return rep, fmt.Errorf("reconcile: list: %w", err)
	}
	for _, h := range running {
		fence, perr := ParseFence(h.ID)
		if perr == nil && fence.Epoch >= a.Ledger.Epoch() {
			// Cannot happen (the epoch just moved), but never kill what
			// might be ours.
			continue
		}
		if err := a.Runtime.Release(ctx, h.ID, false); err != nil {
			log.Printf("reconcile: kill orphan %s: %v", h.ID, err)
			continue
		}
		rep.OrphansKilled++
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "orphan", Fence: fence, FiberID: h.ID, Detail: "killed at boot: prior epoch"})
	}
	a.notify()
	return rep, nil
}

// Sweep is the lease reaper's step: every admitted grant whose lease has
// lapsed is yielded (fibers released, grant revoked). Parked deltas are
// kept; they are the only state that cannot be rebuilt.
func (a *Agent) Sweep(ctx context.Context) int {
	now := a.Ledger.Now()
	n := 0
	for _, st := range a.Ledger.Statuses() {
		g, ok := a.Ledger.Grant(st.GrantUID)
		if ok && g.Expired(now) {
			a.Yield(ctx, g.UID, "lease expired")
			n++
		}
	}
	return n
}
