package core_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
)

type recShipper struct {
	mu   sync.Mutex
	got  []core.AuditRecord
	fail bool
}

func (s *recShipper) Ship(_ context.Context, r core.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("sink down")
	}
	s.got = append(s.got, r)
	return nil
}

func (s *recShipper) setFail(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = v
}

func (s *recShipper) has(event string, seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.got {
		if r.Event == event && r.Seq == seq {
			return true
		}
	}
	return false
}

func TestSpoolSequenceAndDurability(t *testing.T) {
	dir := t.TempDir()
	ship := &recShipper{}
	s, err := core.OpenSpool(dir, ship)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
	if err := s.Append(ctx, core.BestEffort, core.AuditRecord{Event: "clone", Fence: f}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, core.Sync, core.AuditRecord{Event: "park", Fence: f}); err != nil {
		t.Fatal(err)
	}
	// Sync ships before returning; the BestEffort record may or may not
	// have been shipped yet, but the Sync one must be present now.
	if !ship.has("park", 2) {
		t.Fatal("SYNC record not shipped before ack")
	}
	ship.setFail(true)
	if err := s.Append(ctx, core.Sync, core.AuditRecord{Event: "release", Fence: f}); !errors.Is(err, core.ErrAudit) {
		t.Fatalf("SYNC with failing sink = %v, want ErrAudit", err)
	}
	if err := s.Append(ctx, core.BestEffort, core.AuditRecord{Event: "release", Fence: f}); err != nil {
		t.Fatalf("BEST_EFFORT with failing sink = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Sequence resumes from disk on reopen.
	s2, err := core.OpenSpool(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if s2.Seq() != 4 {
		t.Fatalf("resumed seq = %d, want 4", s2.Seq())
	}
	if err := s2.Append(ctx, core.Sync, core.AuditRecord{Event: "attach", Fence: f}); err != nil {
		t.Fatalf("SYNC with no shipper = %v, want local-only success", err)
	}

	fh, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var seqs []uint64
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r core.AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, r.Seq)
	}
	want := []uint64{1, 2, 3, 4, 5}
	if len(seqs) != len(want) {
		t.Fatalf("seqs = %v, want %v", seqs, want)
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("seqs = %v, want %v", seqs, want)
		}
	}
}
