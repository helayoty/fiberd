package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var errSpoolClosed = errors.New("audit: spool closed")

// Events the spool writes itself.
const (
	// EventGap marks missing records, from failed writes (Lost names
	// their sequence numbers) or an unreadable line.
	EventGap = "gap"
	// EventCheckpoint signs the hash of the record before it.
	EventCheckpoint = "checkpoint"

	// DefaultCheckpointEvery is how many records a checkpoint covers.
	DefaultCheckpointEvery = 256

	checkpointContext = "fiberd-audit-v1\n"
)

// AuditRecord is one line of the spool. Every state transition writes one
// record carrying the fence before the caller is acked.
type AuditRecord struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Event   string    `json:"event"` // admit clone attach park release oom expire, gap checkpoint
	Fence   Fence     `json:"fence"`
	Session string    `json:"session,omitempty"`
	FiberID string    `json:"fiber_id,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	// Scope is what the home asserts about where this happened
	// (namespace, service account, fabric claim, ...): facts a reader can
	// check integrity against, empty on a standalone host.
	Scope map[string]string `json:"scope,omitempty"`
	// Lost is the range of sequence numbers a gap stands for, when they
	// were assigned and not written.
	Lost *SeqRange `json:"lost,omitempty"`
	// Signer and Signature are a checkpoint's key ID and its Ed25519
	// signature over the previous record's sequence number and hash.
	Signer    string `json:"signer,omitempty"`
	Signature string `json:"signature,omitempty"`
	// PrevHash is the previous record's Hash. Hash is the SHA-256 of this
	// record with Hash empty. Both are empty before the chain started.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// SeqRange is an inclusive range of sequence numbers.
type SeqRange struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// Auditor records state transitions. Under Sync, Append must not return
// until the record is durable on local disk. The caller acks after it.
type Auditor interface {
	Append(ctx context.Context, d Durability, rec AuditRecord) error
}

// Checkpoints is the key a spool signs checkpoints with and how often.
type Checkpoints struct {
	KeyID string
	Key   ed25519.PrivateKey
	// Every is the number of records between checkpoints. Zero means
	// DefaultCheckpointEvery. A spool also writes one on Close.
	Every int
}

// Spool is the at-least-once, sequence-numbered, hash-chained local log
// under <dir>/audit.jsonl. A Sync record is fsynced before Append returns.
// A BestEffort record is not. Once an fsync has failed the spool refuses
// every Sync record until the process restarts, because the kernel drops
// the pages a failed fsync could not write and a later fsync does not
// retry them.
type Spool struct {
	mu      sync.Mutex
	f       *os.File
	seq     uint64
	prev    string // Hash of the last record written
	newline bool   // the file may not end in a newline, so write one first
	lost    *SeqRange
	lostErr error
	cp      *Checkpoints
	since   int    // records since the last checkpoint
	written uint64 // records written so far, the watermark an fsync covers
	closed  bool   // Close has begun, so Append refuses

	// fsync makes the file durable. Tests replace it.
	fsync func(*os.File) error

	// Group commit. A Sync append writes its record under mu, releases
	// it, then waits for an fsync that began after its write. One fsync
	// runs at a time and covers every record written before it began, so
	// a burst of Sync appends costs one or two fsyncs. A BestEffort append
	// never waits. syncMu guards the fields below.
	syncMu   sync.Mutex
	syncCond *sync.Cond // broadcast when an fsync ends
	syncing  bool       // an fsync is in flight
	synced   uint64     // every record written up to this count is durable
	poison   error      // the first fsync failure. Sticky, so no fsync runs after it
}

// OpenSpool opens or creates the spool, resumes the sequence and the
// chain from the last record on disk, and writes a gap for a torn last
// line. A nil cp writes no checkpoints.
func OpenSpool(dir string, cp *Checkpoints) (*Spool, error) {
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	end, err := scanSpool(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: scan %s: %w", path, err)
	}
	s := &Spool{f: f, seq: end.seq, prev: end.hash, newline: !end.newline, cp: cp, fsync: (*os.File).Sync}
	s.syncCond = sync.NewCond(&s.syncMu)
	if cp != nil && cp.Every <= 0 {
		s.cp = &Checkpoints{KeyID: cp.KeyID, Key: cp.Key, Every: DefaultCheckpointEvery}
	}
	if end.torn >= 0 {
		gap := AuditRecord{Event: EventGap, Detail: fmt.Sprintf("unreadable line at offset %d", end.torn)}
		if err := s.write(&gap); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: %s: %w", path, err)
		}
	}
	if cp == nil {
		log.Printf("audit: no checkpoint key; the chain is not signed")
	}
	return s, nil
}

type spoolEnd struct {
	seq     uint64
	hash    string
	torn    int64 // offset of an unreadable last line, -1 means none
	newline bool  // the file is empty or ends in a newline
}

func scanSpool(f *os.File) (spoolEnd, error) {
	end := spoolEnd{torn: -1, newline: true}
	r := bufio.NewReader(f)
	var off int64
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			end.newline = line[len(line)-1] == '\n'
			if t := bytes.TrimSpace(line); len(t) > 0 {
				var rec AuditRecord
				if json.Unmarshal(t, &rec) != nil {
					end.torn = off
				} else {
					end.torn = -1
					end.seq = max(end.seq, rec.Seq)
					end.hash = rec.Hash
				}
			}
			off += int64(len(line))
		}
		if errors.Is(err, io.EOF) {
			return end, nil
		}
		if err != nil {
			return end, err
		}
	}
}

// Append assigns the next sequence number and writes the line. A Sync
// record is then fsynced before Append returns, or refused with the
// failure once an fsync has failed. A write that fails leaves a gap the
// next one records.
func (s *Spool) Append(_ context.Context, d Durability, rec AuditRecord) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrAudit, errSpoolClosed)
	}
	s.writeGap()
	if err := s.write(&rec); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	if s.cp != nil && s.since >= s.cp.Every {
		s.checkpoint()
	}
	n := s.written
	s.mu.Unlock()
	if d != Sync {
		return nil
	}
	if err := s.syncThrough(n); err != nil {
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	return nil
}

// syncThrough returns once an fsync that began after the n-th write has
// completed, which is what makes that write durable. The first caller to
// find no fsync in flight leads one and the others wait. A caller it did
// not cover leads the next.
//
// A failed fsync poisons the spool. Only a write an earlier fsync already
// made durable returns nil after that. Every other caller, waiting now or
// arriving later, gets the failure, and no fsync is led again.
func (s *Spool) syncThrough(n uint64) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	for {
		switch {
		case s.synced >= n:
			return nil
		case s.poison != nil:
			return s.poison
		case s.syncing:
			s.syncCond.Wait()
			continue
		}
		s.syncing = true
		s.mu.Lock()
		f, fsync, upto := s.f, s.fsync, s.written
		s.mu.Unlock()
		s.syncMu.Unlock()
		err := fsync(f)
		s.syncMu.Lock()
		s.syncing = false
		if err != nil {
			s.poison = err
			log.Printf("audit: fsync failed, sync records are refused until restart: %v", err)
		} else {
			s.synced = max(s.synced, upto)
		}
		s.syncCond.Broadcast()
	}
}

// write assigns rec the next sequence number, chains and writes it. On
// failure the number joins the lost range. s.mu is held.
func (s *Spool) write(rec *AuditRecord) error {
	s.seq++
	rec.Seq = s.seq
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	rec.PrevHash, rec.Hash = s.prev, ""
	h, err := recordHash(*rec)
	if err == nil {
		rec.Hash = h
		var b []byte
		if b, err = json.Marshal(rec); err == nil {
			if s.newline {
				b = append([]byte{'\n'}, b...)
			}
			_, err = s.f.Write(append(b, '\n'))
		}
	}
	if err != nil {
		// A partial line may be on disk, so the next write starts a new one.
		s.newline = true
		if s.lost == nil {
			s.lost, s.lostErr = &SeqRange{From: rec.Seq}, err
		}
		s.lost.To = rec.Seq
		return err
	}
	s.newline = false
	s.prev = rec.Hash
	s.since++
	s.written++
	return nil
}

// writeGap records the sequence numbers lost since the last write that
// succeeded. s.mu is held.
func (s *Spool) writeGap() {
	if s.lost == nil {
		return
	}
	gap := AuditRecord{Event: EventGap, Lost: s.lost, Detail: s.lostErr.Error()}
	lost := s.lost
	s.lost = nil
	if err := s.write(&gap); err != nil {
		s.lost.From = lost.From
	}
}

// checkpoint signs the last record written. s.mu is held.
func (s *Spool) checkpoint() {
	sig := ed25519.Sign(s.cp.Key, checkpointPayload(s.seq, s.prev))
	cp := AuditRecord{Event: EventCheckpoint, Signer: s.cp.KeyID, Signature: base64.RawURLEncoding.EncodeToString(sig)}
	if err := s.write(&cp); err != nil {
		log.Printf("audit: checkpoint seq=%d: %v", cp.Seq, err)
		return
	}
	s.since = 0
}

// Close signs what the last checkpoint does not cover, fsyncs and closes
// the file. A poisoned spool still closes, and Close returns the fsync
// failure instead of fsyncing again.
func (s *Spool) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSpoolClosed
	}
	s.closed = true
	s.writeGap()
	if s.cp != nil && s.since > 0 {
		s.checkpoint()
	}
	n := s.written
	s.mu.Unlock()
	// Through the group path, so an fsync in flight ends before the file
	// closes under it.
	serr := s.syncThrough(n)
	s.mu.Lock()
	defer s.mu.Unlock()
	if serr != nil {
		_ = s.f.Close()
		return serr
	}
	return s.f.Close()
}

func recordHash(rec AuditRecord) (string, error) {
	rec.Hash = ""
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func checkpointPayload(seq uint64, hash string) []byte {
	return []byte(checkpointContext + strconv.FormatUint(seq, 10) + " " + hash)
}

// SpoolReport is what VerifySpool found.
type SpoolReport struct {
	// Records is the number of chained records, gaps and checkpoints
	// included. Unchained is how many came before the chain started.
	Records, Unchained int
	Gaps               []AuditRecord
	Checkpoints        int
	// SignedSeq is the last record a checkpoint covers. Unsigned is how
	// many chained records follow it. A spool cut after its last
	// checkpoint still verifies. Only a copy held elsewhere can show it.
	SignedSeq uint64
	Unsigned  int
	// TornTail means the last line is unreadable and no gap follows it
	// yet. The spool records one when it is next opened.
	TornTail bool
}

// VerifySpool checks the spool at path. Every record's hash must hold and
// chain to the last, so no edit, removal or reordering goes unnoticed.
// Sequence numbers advance by one except across a gap that names the
// missing ones. An unreadable line must be followed by a gap. Every
// checkpoint must be signed by a key in trust.
func VerifySpool(path string, trust map[string]ed25519.PublicKey) (SpoolReport, error) {
	var rep SpoolReport
	f, err := os.Open(path)
	if err != nil {
		return rep, err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	var prev *AuditRecord
	torn := 0 // line number of an unreadable line not yet followed by a gap
	fail := func(n int, format string, a ...any) (SpoolReport, error) {
		return rep, fmt.Errorf("%w: line %d: %s", ErrAuditChain, n, fmt.Sprintf(format, a...))
	}
	for n := 1; ; n++ {
		line, err := r.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return rep, err
		}
		if t := bytes.TrimSpace(line); len(t) > 0 {
			var rec AuditRecord
			switch {
			case json.Unmarshal(t, &rec) != nil:
				if prev == nil {
					rep.Unchained++
				} else if torn == 0 {
					torn = n
				}
			case rec.Hash == "":
				if prev != nil {
					return fail(n, "seq %d is not chained", rec.Seq)
				}
				rep.Unchained++
			default:
				if h, err := recordHash(rec); err != nil || h != rec.Hash {
					return fail(n, "seq %d: the hash does not match the record", rec.Seq)
				}
				want := uint64(0)
				if prev == nil {
					if rec.PrevHash != "" {
						return fail(n, "the chain starts at seq %d, which follows a record that is not here", rec.Seq)
					}
				} else {
					if rec.PrevHash != prev.Hash {
						return fail(n, "seq %d does not follow seq %d", rec.Seq, prev.Seq)
					}
					want = prev.Seq + 1
					if rec.Event == EventGap && rec.Lost != nil {
						if rec.Lost.From != want || rec.Lost.To < rec.Lost.From {
							return fail(n, "gap seq %d names %d-%d, after seq %d", rec.Seq, rec.Lost.From, rec.Lost.To, prev.Seq)
						}
						want = rec.Lost.To + 1
					}
					if rec.Seq != want {
						return fail(n, "seq %d follows seq %d", rec.Seq, prev.Seq)
					}
				}
				if torn != 0 && rec.Event != EventGap {
					return fail(torn, "unreadable, and no gap follows it")
				}
				torn = 0
				switch rec.Event {
				case EventGap:
					rep.Gaps = append(rep.Gaps, rec)
					rep.Unsigned++
				case EventCheckpoint:
					if prev == nil {
						return fail(n, "checkpoint seq %d signs nothing", rec.Seq)
					}
					pub, ok := trust[rec.Signer]
					if !ok {
						return fail(n, "checkpoint seq %d: signer %q is not trusted", rec.Seq, rec.Signer)
					}
					sig, err := base64.RawURLEncoding.DecodeString(rec.Signature)
					if err != nil || !ed25519.Verify(pub, checkpointPayload(prev.Seq, prev.Hash), sig) {
						return fail(n, "checkpoint seq %d: the signature does not hold", rec.Seq)
					}
					rep.Checkpoints++
					rep.SignedSeq, rep.Unsigned = rec.Seq, 0
				default:
					rep.Unsigned++
				}
				rep.Records++
				prev = &rec
			}
		}
		if errors.Is(err, io.EOF) {
			rep.TornTail = torn != 0
			return rep, nil
		}
	}
}
