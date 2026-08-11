package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Fence identifies one incarnation of a fiber. It is minted fresh on every
// resume and create, never reused, and every credential and claim is scoped
// to it: nothing outlives min(lease TTL, fence).
type Fence struct {
	GrantUID string
	Epoch    uint64 // agent incarnation — bumped on every agent start
	Seq      uint64 // fiber incarnation within (grant, epoch)
}

func (f Fence) String() string {
	return fmt.Sprintf("%s/%d/%d", f.GrantUID, f.Epoch, f.Seq)
}

// Newer reports whether f supersedes o for the same grant. A caller holding
// an older fence is detectably stale regardless of which path it raced.
func (f Fence) Newer(o Fence) bool {
	if f.GrantUID != o.GrantUID {
		return false
	}
	if f.Epoch != o.Epoch {
		return f.Epoch > o.Epoch
	}
	return f.Seq > o.Seq
}

// EpochStore persists the agent's incarnation counter. The epoch file is the
// only state that must never be lost silently: on any read failure the safe
// response is a large forward jump (timestamp-derived), which preserves the
// monotonicity guarantee at the cost of invalidating fences that were already
// invalid in spirit.
type EpochStore struct {
	path  string
	epoch atomic.Uint64
}

func OpenEpochStore(dir string) (*EpochStore, error) {
	s := &EpochStore{path: filepath.Join(dir, "epoch")}
	prev, err := s.read()
	next := prev + 1
	if err != nil {
		// Corrupt or unreadable: jump, don't guess.
		next = uint64(time.Now().Unix())
	}
	if err := s.write(next); err != nil {
		return nil, fmt.Errorf("persist epoch: %w", err)
	}
	s.epoch.Store(next)
	return s, nil
}

func (s *EpochStore) Current() uint64 { return s.epoch.Load() }

func (s *EpochStore) read() (uint64, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // first boot
		}
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func (s *EpochStore) write(v uint64) error {
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
