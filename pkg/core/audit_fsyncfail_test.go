package core_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestSpoolFsyncFailure pins what a failed fsync means. Every sync append
// whose record no earlier fsync made durable returns ErrAudit wrapping the
// fsync error, whether it led the fsync, waited on it, or wrote while it
// ran. The failure is sticky. A later sync append is refused without
// another fsync, a best-effort append still lands, Close returns the
// failure, and what is on disk still verifies.
//
// The first fsync is held until every waiter has written its record.
// failOn says which fsync call fails: the first (the leader alone is
// covered) or the second (the group fsync covering every waiter).
func TestSpoolFsyncFailure(t *testing.T) {
	cases := []struct {
		name      string
		waiters   int // sync appends written while the first fsync is held
		failOn    int // the fsync call that fails
		wantFail  int // appends that must return the fsync error
		wantCalls int // fsyncs in all, none after the failure
	}{
		{name: "a lone sync append sees its own fsync fail", waiters: 0, failOn: 1, wantFail: 1, wantCalls: 1},
		{name: "appends written while the failing fsync ran fail too", waiters: 8, failOn: 1, wantFail: 9, wantCalls: 1},
		{name: "a failed group fsync fails every waiter but not the leader an earlier fsync covered", waiters: 8, failOn: 2, wantFail: 8, wantCalls: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := core.OpenSpool(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
			boom := errors.New("EIO")

			var (
				mu    sync.Mutex
				calls int
			)
			entered, release := make(chan struct{}), make(chan struct{})
			core.SetSpoolFsync(s, func(fh *os.File) error {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if n == 1 {
					close(entered)
					<-release
				}
				if n == tc.failOn {
					return boom
				}
				return fh.Sync()
			})
			fsyncs := func() int {
				mu.Lock()
				defer mu.Unlock()
				return calls
			}

			type res struct {
				who string
				err error
			}
			results := make(chan res, 1+tc.waiters)
			go func() {
				results <- res{"leader", s.Append(ctx, core.Sync, core.AuditRecord{Event: "park", Fence: f, Detail: "leader"})}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no fsync started")
			}
			for i := 0; i < tc.waiters; i++ {
				go func() {
					results <- res{"waiter", s.Append(ctx, core.Sync, core.AuditRecord{Event: "park", Fence: f, Detail: "waiter"})}
				}()
			}
			for s.Seq() < uint64(1+tc.waiters) {
				time.Sleep(time.Millisecond)
			}
			close(release)
			failed := 0
			for i := 0; i < 1+tc.waiters; i++ {
				r := <-results
				switch {
				case r.err == nil:
				case errors.Is(r.err, core.ErrAudit) && errors.Is(r.err, boom):
					failed++
				default:
					t.Fatalf("%s append = %v, want nil or ErrAudit wrapping the fsync error", r.who, r.err)
				}
			}
			if failed != tc.wantFail {
				t.Fatalf("appends that failed = %d, want %d", failed, tc.wantFail)
			}
			if n := fsyncs(); n != tc.wantCalls {
				t.Fatalf("fsyncs = %d, want %d", n, tc.wantCalls)
			}
			// The failure is sticky. A later sync append is refused without
			// another fsync, since a later fsync would not make it durable.
			err = s.Append(ctx, core.Sync, core.AuditRecord{Event: "park", Fence: f, Detail: "after"})
			if !errors.Is(err, core.ErrAudit) || !errors.Is(err, boom) {
				t.Fatalf("sync append after a failed fsync = %v, want ErrAudit wrapping the fsync error", err)
			}
			if n := fsyncs(); n != tc.wantCalls {
				t.Fatalf("fsyncs after the failure = %d, want %d still", n, tc.wantCalls)
			}
			// A best-effort append never waited on fsync and still lands.
			if err := s.Append(ctx, core.BestEffort, core.AuditRecord{Event: "park", Fence: f, Detail: "best-effort"}); err != nil {
				t.Fatalf("best-effort append after a failed fsync = %v, want nil", err)
			}
			if seqs := journalSeqs(t, dir); len(seqs) != 3+tc.waiters {
				t.Fatalf("records on disk = %d, want %d", len(seqs), 3+tc.waiters)
			}
			// Close still closes the file and reports the failure.
			if err := s.Close(); !errors.Is(err, boom) {
				t.Fatalf("Close after a failed fsync = %v, want the fsync error", err)
			}
			if n := fsyncs(); n != tc.wantCalls {
				t.Fatalf("fsyncs after Close = %d, want %d still", n, tc.wantCalls)
			}
			if _, err := core.VerifySpool(dir+"/audit.jsonl", nil); err != nil {
				t.Fatalf("VerifySpool: %v", err)
			}
		})
	}
}
