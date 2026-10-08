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
// no earlier fsync made durable gets ErrAudit wrapping the fsync error,
// whether it led, waited or wrote during the fsync. The failure is sticky.
// Later sync appends are refused without an fsync, best-effort appends
// still land, Close returns the failure, and the disk still verifies.
//
// The first fsync is held until every waiter has written its record.
// failOn picks the failing fsync, the leader's own or the group one.
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

// TestSpoolPoisoned pins what Poisoned reports, since /healthz turns it
// into a 503. It is nil until an fsync fails, then the fsync error, and
// it stays so after Close. A best-effort append runs no fsync, so a
// failing fsync poisons the spool only at Close, which fsyncs.
func TestSpoolPoisoned(t *testing.T) {
	boom := errors.New("EIO")
	cases := []struct {
		name  string
		fsync func(*os.File) error
		d     core.Durability
		want  error // after the append
		close error // after Close
	}{
		{name: "a healthy spool reports nil", fsync: (*os.File).Sync, d: core.Sync},
		{name: "a failed fsync poisons the spool", fsync: func(*os.File) error { return boom }, d: core.Sync, want: boom, close: boom},
		{name: "best effort runs no fsync until Close", fsync: func(*os.File) error { return boom }, d: core.BestEffort, close: boom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := core.OpenSpool(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Poisoned(); err != nil {
				t.Fatalf("Poisoned on a new spool = %v, want nil", err)
			}
			core.SetSpoolFsync(s, tc.fsync)
			_ = s.Append(context.Background(), tc.d, core.AuditRecord{Event: "park", Fence: core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}})
			if got := s.Poisoned(); !errors.Is(got, tc.want) || (tc.want == nil) != (got == nil) {
				t.Fatalf("Poisoned = %v, want %v", got, tc.want)
			}
			_ = s.Close()
			if got := s.Poisoned(); !errors.Is(got, tc.close) || (tc.close == nil) != (got == nil) {
				t.Fatalf("Poisoned after Close = %v, want %v", got, tc.close)
			}
		})
	}
}
