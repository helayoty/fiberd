package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// DefaultRevokeTTL is how long a removed grant stays denied past its
// lease when the home has no -max-lease to bound its tokens by.
const DefaultRevokeTTL = 24 * time.Hour

// Revoked is the home's deny-list of grant UIDs its lane removed. Each
// stays until every token for it has expired. Admit refuses them, so a
// token a caller still holds cannot re-admit what the home took away. It
// lives in its own file, not the ledger snapshot, because an unreadable
// snapshot is treated as empty and a deny-list must never be.
type Revoked struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	// until is when each entry lapses. The zero time means never, since a
	// grant with no lease has tokens that never expire.
	until map[string]time.Time
}

// OpenRevoked loads the deny-list at path (none yet is an empty one) and
// drops the entries that lapsed. A file that does not read is an error.
// ttl is how long an entry is kept past the latest lease it knows. Set
// it to the longest lease the issuer may sign.
func OpenRevoked(path string, ttl time.Duration, now time.Time) (*Revoked, error) {
	if ttl <= 0 {
		ttl = DefaultRevokeTTL
	}
	r := &Revoked{path: path, ttl: ttl, until: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &r.until); err != nil {
		return nil, fmt.Errorf("revoked: %s unreadable: %w", path, err)
	}
	for uid, t := range r.until {
		if !t.IsZero() && !now.Before(t) {
			delete(r.until, uid)
		}
	}
	return r, nil
}

// Add denies uid until the later of lease and now plus the ttl, or for
// good when lease is zero (no lease).
func (r *Revoked) Add(uid string, lease, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	until := lease
	if !lease.IsZero() && now.Add(r.ttl).After(lease) {
		until = now.Add(r.ttl)
	}
	if old, ok := r.until[uid]; !ok || outlasts(until, old) {
		r.until[uid] = until
	}
	return r.save()
}

// Denied reports whether uid is denied at now. A denied token whose lease
// runs past the entry extends it, so that token stays refused.
func (r *Revoked) Denied(uid string, lease, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.until[uid]
	if !ok {
		return false
	}
	if !until.IsZero() && !now.Before(until) {
		delete(r.until, uid)
		r.saveOrLog(uid)
		return false
	}
	if outlasts(lease, until) {
		r.until[uid] = lease
		r.saveOrLog(uid)
	}
	return true
}

// outlasts reports whether a denial until a runs past one until b. The
// zero time means never.
func outlasts(a, b time.Time) bool {
	return !b.IsZero() && (a.IsZero() || a.After(b))
}

// Clear lifts uid's entry and reports whether there was one. It runs when
// the lane delivers the grant again.
func (r *Revoked) Clear(uid string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.until[uid]; !ok {
		return false, nil
	}
	delete(r.until, uid)
	return true, r.save()
}

// saveOrLog saves the list after Denied changed uid's entry. The entry
// holds in memory either way. On disk it may be the older one until the
// next save. r.mu is held.
func (r *Revoked) saveOrLog(uid string) {
	if err := r.save(); err != nil {
		log.Printf("WARNING: revoked %s: persisting the deny-list: %v", uid, err)
	}
}

// save writes the list atomically. r.mu is held.
func (r *Revoked) save() error {
	b, err := json.Marshal(r.until)
	if err != nil {
		return err
	}
	return writeFileAtomic(r.path, b, 0o600)
}
