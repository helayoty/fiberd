package core

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestFailedFsyncIsNotForgivenByALaterSuccess drives syncThrough through
// the fsyncgate scenario. On Linux a failed fsync drops the pages it could
// not write, so a later success does not make the earlier write durable.
// Its waiter must get the failure, a later sync append is refused without
// an fsync, and only writes an earlier fsync covered stay durable.
//
// prewritten records stand for waiters that wrote before the leader's
// fsync began. Their re-check is the direct syncThrough call at the end.
func TestFailedFsyncIsNotForgivenByALaterSuccess(t *testing.T) {
	cases := []struct {
		name       string
		okFirst    int    // sync appends that succeed before the failure
		prewritten int    // records written before the failing fsync, by waiters that lead nothing
		durable    uint64 // the last write syncThrough may still report durable
	}{
		{name: "the first fsync fails and a second would succeed", durable: 0},
		{name: "a waiter that wrote before the failing fsync is not forgiven", prewritten: 1, durable: 0},
		{name: "a write an earlier fsync made durable stays durable", okFirst: 1, durable: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenSpool(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			f := Fence{GrantUID: "g", Epoch: 1, Seq: 1}
			boom := errors.New("EIO")
			failOn := tc.okFirst + 1
			calls := 0
			s.fsync = func(fh *os.File) error {
				calls++
				if calls == failOn {
					return boom
				}
				return fh.Sync()
			}
			for i := 0; i < tc.okFirst; i++ {
				if err := s.Append(ctx, Sync, AuditRecord{Event: "park", Fence: f}); err != nil {
					t.Fatalf("append %d before the failure = %v", i+1, err)
				}
			}
			for i := 0; i < tc.prewritten; i++ {
				s.mu.Lock()
				err := s.write(&AuditRecord{Event: "park", Fence: f})
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			// The leader's fsync covers every write so far and fails.
			err = s.Append(ctx, Sync, AuditRecord{Event: "park", Fence: f})
			if !errors.Is(err, ErrAudit) || !errors.Is(err, boom) {
				t.Fatalf("the append that led the failing fsync = %v, want ErrAudit wrapping it", err)
			}
			if calls != failOn {
				t.Fatalf("fsyncs = %d, want %d", calls, failOn)
			}
			// A later sync append would have led an fsync that succeeds.
			// It is refused instead, and no fsync runs. Errorf, not Fatalf,
			// so the waiters' re-check below is reported either way.
			err = s.Append(ctx, Sync, AuditRecord{Event: "park", Fence: f})
			if !errors.Is(err, ErrAudit) || !errors.Is(err, boom) {
				t.Errorf("sync append after the failure = %v, want ErrAudit wrapping it", err)
			}
			if calls != failOn {
				t.Errorf("fsyncs after the failure = %d, want %d still", calls, failOn)
			}
			// Every waiter's re-check, write by write.
			s.mu.Lock()
			written := s.written
			s.mu.Unlock()
			for n := uint64(1); n <= written; n++ {
				got := s.syncThrough(n)
				if n <= tc.durable && got != nil {
					t.Fatalf("syncThrough(%d) = %v, want nil for a write an earlier fsync covered", n, got)
				}
				if n > tc.durable && !errors.Is(got, boom) {
					t.Fatalf("syncThrough(%d) = %v, want the fsync failure", n, got)
				}
			}
			if err := s.Append(ctx, BestEffort, AuditRecord{Event: "park", Fence: f}); err != nil {
				t.Fatalf("best-effort append after the failure = %v, want nil", err)
			}
			if err := s.Close(); !errors.Is(err, boom) {
				t.Fatalf("Close = %v, want the fsync failure", err)
			}
		})
	}
}
