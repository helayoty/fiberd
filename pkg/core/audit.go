package core

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditRecord is one line of the spool. Every state transition writes one
// record carrying the fence before the caller is acked.
type AuditRecord struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Event   string    `json:"event"` // admit clone attach park release oom expire
	Fence   Fence     `json:"fence"`
	Session string    `json:"session,omitempty"`
	FiberID string    `json:"fiber_id,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	// Scope is what the home asserts about where this happened
	// (namespace, service account, fabric claim, ...): facts a reader can
	// check integrity against, empty on a standalone host.
	Scope map[string]string `json:"scope,omitempty"`
}

// Auditor is append-locally, ship-async. Under Sync, Append must not
// return until the record is remote; the caller acks after it.
type Auditor interface {
	Append(ctx context.Context, d Durability, rec AuditRecord) error
}

// Shipper is the remote sink. Nil means "no sink configured": Sync then
// degrades to a local fsync, and the spool says so once at open.
type Shipper interface {
	Ship(ctx context.Context, rec AuditRecord) error
}

// NopAuditor discards everything. Tests only.
type NopAuditor struct{}

func (NopAuditor) Append(context.Context, Durability, AuditRecord) error { return nil }

var ErrAudit = errors.New("audit: record not durable")

// Spool is the at-least-once, sequence-numbered local log under
// <dir>/audit.jsonl. BestEffort records are queued for asynchronous
// shipping after the append; Sync records are shipped before Append
// returns.
type Spool struct {
	mu      sync.Mutex
	f       *os.File
	w       *bufio.Writer
	seq     uint64
	shipper Shipper
	queue   chan AuditRecord
	done    chan struct{}
}

// OpenSpool opens or creates the spool and resumes the sequence from the
// last record on disk.
func OpenSpool(dir string, shipper Shipper) (*Spool, error) {
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	seq, err := lastSeq(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: scan %s: %w", path, err)
	}
	s := &Spool{f: f, w: bufio.NewWriter(f), seq: seq, shipper: shipper,
		queue: make(chan AuditRecord, 1024), done: make(chan struct{})}
	if shipper == nil {
		log.Printf("audit: no shipper configured; SYNC records are fsynced locally only")
	}
	go s.ship()
	return s, nil
}

func lastSeq(f *os.File) (uint64, error) {
	var last uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r AuditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // a torn tail line is tolerated; seq still moves forward
		}
		if r.Seq > last {
			last = r.Seq
		}
	}
	return last, sc.Err()
}

// Append assigns the next sequence number, writes the line, and then
// either queues (BestEffort) or ships (Sync) the record.
func (s *Spool) Append(ctx context.Context, d Durability, rec AuditRecord) error {
	s.mu.Lock()
	s.seq++
	rec.Seq = s.seq
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	b, err := json.Marshal(rec)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	if err := s.w.Flush(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	if d == Sync {
		if err := s.f.Sync(); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("%w: %w", ErrAudit, err)
		}
	}
	s.mu.Unlock()

	if d == Sync {
		if s.shipper == nil {
			return nil
		}
		if err := s.shipper.Ship(ctx, rec); err != nil {
			return fmt.Errorf("%w: ship: %w", ErrAudit, err)
		}
		return nil
	}
	select {
	case s.queue <- rec:
	default:
		// Queue full: the record is on disk; the shipper will not see it
		// until a replay. Loss window is declared, not hidden.
		log.Printf("audit: ship queue full, seq=%d deferred to replay", rec.Seq)
	}
	return nil
}

func (s *Spool) ship() {
	defer close(s.done)
	for rec := range s.queue {
		if s.shipper == nil {
			continue
		}
		if err := s.shipper.Ship(context.Background(), rec); err != nil {
			log.Printf("audit: ship seq=%d: %v", rec.Seq, err)
		}
	}
}

// Close flushes the queue and closes the file.
func (s *Spool) Close() error {
	close(s.queue)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.Flush(); err != nil {
		return err
	}
	return s.f.Close()
}

// Seq returns the last assigned sequence number.
func (s *Spool) Seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}
