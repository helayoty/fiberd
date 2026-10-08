package core_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestSpoolSequenceAndDurability walks one spool directory in order.
//   - every record gets the next sequence number, lands on disk and chains
//     to the one before it
//   - SYNC and BEST_EFFORT appends both succeed locally
//   - the sequence resumes from disk on reopen
//   - with a key, a signed checkpoint follows every Every records and
//     closes the spool
//   - a torn last line and a failed write each leave a gap record
//   - VerifySpool accepts the result and refuses it edited
func TestSpoolSequenceAndDurability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cp := &core.Checkpoints{KeyID: "audit-1", Key: priv, Every: 2}
	trust := map[string]ed25519.PublicKey{"audit-1": pub}
	s, err := core.OpenSpool(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	ctx := context.Background()
	f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
	const final = "records=12 unchained=0 checkpoints=3 signed=13 unsigned=0 torn=false gaps=[7:- 9:8-8]"
	steps := []struct {
		name        string
		reopen      bool              // close the spool and reopen it first
		cp          *core.Checkpoints // the reopened spool's key
		tear        string            // appended to the closed spool before the reopen
		failWrite   bool              // the append's write fails
		dur         core.Durability
		event       string // record to append, "" means none
		wantErr     error
		wantSeq     uint64   // resumed sequence after reopen, 0 means unchecked
		wantJournal []uint64 // sequence numbers on disk after the step, nil means unchecked
		wantReport  string   // VerifySpool's summary after the step, "" means unchecked
	}{
		{name: "best-effort append is accepted", dur: core.BestEffort, event: "clone"},
		{name: "sync append is accepted", dur: core.Sync, event: "park"},
		{name: "sequence resumes from disk on reopen", reopen: true, dur: core.Sync, event: "attach", wantSeq: 2},
		{name: "the journal holds every record in sequence, chained", wantJournal: []uint64{1, 2, 3},
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[]"},
		{name: "with a key, the chain resumes on reopen", reopen: true, cp: cp, dur: core.BestEffort, event: "clone", wantSeq: 3},
		{name: "a checkpoint signs every second record", dur: core.Sync, event: "park", wantJournal: []uint64{1, 2, 3, 4, 5, 6},
			wantReport: "records=6 unchained=0 checkpoints=1 signed=6 unsigned=0 torn=false gaps=[]"},
		{name: "a torn last line is a gap on reopen", reopen: true, cp: cp, tear: `{"seq":7,"event":"cl`, wantSeq: 7,
			wantReport: "records=7 unchained=0 checkpoints=1 signed=6 unsigned=1 torn=false gaps=[7:-]"},
		{name: "a write that fails is ErrAudit", failWrite: true, dur: core.Sync, event: "release", wantErr: core.ErrAudit},
		{name: "the next write records the gap first", dur: core.Sync, event: "attach",
			wantJournal: []uint64{1, 2, 3, 4, 5, 6, 7, 9, 10, 11},
			wantReport:  "records=10 unchained=0 checkpoints=2 signed=11 unsigned=0 torn=false gaps=[7:- 9:8-8]"},
		{name: "a record after the last checkpoint", dur: core.BestEffort, event: "clone",
			wantReport: "records=11 unchained=0 checkpoints=2 signed=11 unsigned=1 torn=false gaps=[7:- 9:8-8]"},
		{name: "close signs the rest", reopen: true, wantSeq: 13, wantReport: final},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			if tc.reopen {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if tc.tear != "" {
					appendFile(t, path, tc.tear)
				}
				if s, err = core.OpenSpool(dir, tc.cp); err != nil {
					t.Fatal(err)
				}
			}
			if tc.wantSeq != 0 && s.Seq() != tc.wantSeq {
				t.Fatalf("resumed seq = %d, want %d", s.Seq(), tc.wantSeq)
			}
			if tc.event != "" {
				if tc.failWrite {
					ro, err := os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					old := core.SwapSpoolFile(s, ro)
					defer func() { core.SwapSpoolFile(s, old); _ = ro.Close() }()
				}
				if err := s.Append(ctx, tc.dur, core.AuditRecord{Event: tc.event, Fence: f}); !errors.Is(err, tc.wantErr) {
					t.Fatalf("Append(%s) = %v, want %v", tc.event, err, tc.wantErr)
				}
			}
			if tc.wantJournal != nil {
				if seqs := journalSeqs(t, dir); !slices.Equal(seqs, tc.wantJournal) {
					t.Fatalf("seqs = %v, want %v", seqs, tc.wantJournal)
				}
			}
			if tc.wantReport != "" {
				rep, err := core.VerifySpool(path, trust)
				if err != nil {
					t.Fatal(err)
				}
				if got := summary(rep); got != tc.wantReport {
					t.Fatalf("report = %s, want %s", got, tc.wantReport)
				}
			}
		}) {
			return // later steps build on this one
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	at := func(seq uint64) int {
		for i, l := range lines {
			var r core.AuditRecord
			if json.Unmarshal([]byte(l), &r) == nil && r.Seq == seq && r.Hash != "" {
				return i
			}
		}
		t.Fatalf("seq %d not in the spool", seq)
		return -1
	}
	edit := func(seq uint64, from, to string) func([]string) []string {
		return func(l []string) []string { l[at(seq)] = strings.Replace(l[at(seq)], from, to, 1); return l }
	}
	tamper := []struct {
		name   string
		mutate func([]string) []string
		trust  map[string]ed25519.PublicKey // nil = the spool's key
		want   string                       // summary, "" means wantErr
		// wantErr is the error when want is "". Nil means ErrAuditChain.
		wantErr error
		missing bool // no file to verify
		dir     bool // the path is a directory, which opens and does not read
	}{
		{name: "the spool as written verifies", mutate: func(l []string) []string { return l }, want: final},
		{name: "an edited record", mutate: edit(2, `"event":"park"`, `"event":"attach"`)},
		{name: "a removed record", mutate: func(l []string) []string { return slices.Delete(l, at(3), at(3)+1) }},
		{name: "two records swapped", mutate: func(l []string) []string { i, j := at(3), at(4); l[i], l[j] = l[j], l[i]; return l }},
		{name: "an edited record re-chained without the key", mutate: func(l []string) []string {
			return rechain(t, edit(2, `"event":"park"`, `"event":"attach"`)(l))
		}},
		{name: "a checkpoint signed by another key", mutate: func(l []string) []string {
			i := at(6)
			var r core.AuditRecord
			_ = json.Unmarshal([]byte(l[i]), &r)
			r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, []byte("fiberd-audit-v1\n5 "+r.PrevHash)))
			b, _ := json.Marshal(r)
			l[i] = string(b)
			return rechain(t, l)
		}},
		{name: "a checkpoint by a signer not trusted", mutate: func(l []string) []string { return l }, trust: map[string]ed25519.PublicKey{}},
		{name: "an unreadable line with no gap after it", mutate: func(l []string) []string { return slices.Insert(l, at(5)+1, "garbage") }},
		// Cutting the tail after a checkpoint is not detectable here. The
		// report says how much the last checkpoint covers.
		{name: "the closing checkpoint cut off", mutate: func(l []string) []string { return l[:len(l)-1] },
			want: "records=11 unchained=0 checkpoints=2 signed=11 unsigned=1 torn=false gaps=[7:- 9:8-8]"},
		{name: "a torn last line", mutate: func(l []string) []string { return append(l, `{"seq":14`) },
			want: "records=12 unchained=0 checkpoints=3 signed=13 unsigned=0 torn=true gaps=[7:- 9:8-8]"},
		{name: "records from before the chain", mutate: func(l []string) []string { return append([]string{`{"seq":0,"event":"admit"}`}, l...) },
			want: "records=12 unchained=1 checkpoints=3 signed=13 unsigned=0 torn=false gaps=[7:- 9:8-8]"},
		{name: "an unreadable line from before the chain", mutate: func(l []string) []string { return append([]string{"garbage"}, l...) },
			want: "records=12 unchained=1 checkpoints=3 signed=13 unsigned=0 torn=false gaps=[7:- 9:8-8]"},
		{name: "an unchained record after the chain started", mutate: func(l []string) []string {
			return slices.Insert(l, at(3)+1, `{"seq":4,"event":"admit"}`)
		}},
		{name: "a chain that starts after a record that is not here", mutate: func(l []string) []string { return slices.Delete(l, at(1), at(1)+1) }},
		{name: "a gap that names the wrong range", mutate: func(l []string) []string {
			return rechain(t, edit(9, `"from":8`, `"from":7`)(l))
		}},
		{name: "a sequence number skipped", mutate: func(l []string) []string {
			return rechain(t, edit(12, `"seq":12`, `"seq":14`)(l))
		}},
		{name: "a checkpoint that signs nothing", mutate: func(l []string) []string { return rechain(t, []string{l[at(6)]}) }},
		{name: "a spool that is not there", missing: true, wantErr: fs.ErrNotExist},
		{name: "a spool that does not read", dir: true},
	}
	for _, tc := range tamper {
		t.Run("verify: "+tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			if tc.dir {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.missing && !tc.dir {
				if err := os.WriteFile(p, []byte(strings.Join(tc.mutate(slices.Clone(lines)), "\n")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			tr := trust
			if tc.trust != nil {
				tr = tc.trust
			}
			rep, err := core.VerifySpool(p, tr)
			if tc.want == "" {
				if tc.dir {
					if err == nil || errors.Is(err, core.ErrAuditChain) {
						t.Fatalf("VerifySpool = %s, %v; want a read error", summary(rep), err)
					}
					return
				}
				wantErr := tc.wantErr
				if wantErr == nil {
					wantErr = core.ErrAuditChain
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("VerifySpool = %s, %v; want %v", summary(rep), err, wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := summary(rep); got != tc.want {
				t.Fatalf("report = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestSpoolGroupCommit checks that N concurrent sync appends cost fewer
// than N fsyncs. Each still returns only once an fsync covering its record
// has completed. A best-effort append never waits on an fsync in flight,
// and the journal stays in sequence and chained. The test holds the first
// fsync until every record is written, so the other appends pile up
// behind it.
func TestSpoolGroupCommit(t *testing.T) {
	cases := []struct {
		name       string
		sync       int // concurrent sync appends
		bestEffort int // best-effort appends made while the first fsync is held
		wantSyncs  int // fsyncs at most, and every row wants at least one
	}{
		{name: "one sync append is one fsync", sync: 1, wantSyncs: 1},
		{name: "32 concurrent sync appends share at most two fsyncs", sync: 32, wantSyncs: 2},
		{name: "best-effort appends return while an fsync is in flight", sync: 4, bestEffort: 8, wantSyncs: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			s, err := core.OpenSpool(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}

			var (
				mu        sync.Mutex
				syncs     int      // completed fsyncs
				coveredAt []uint64 // the largest seq on disk when each fsync ran
				held      bool     // the first fsync has been held
				returned  int      // sync appends that have returned
			)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			let := func() { releaseOnce.Do(func() { close(release) }) }
			// Cleanup lets the held fsync go and waits for every append,
			// also when a step failed, before the spool closes under them.
			var wg sync.WaitGroup
			done := make(chan struct{}) // the best-effort appends and the write poll are finished
			defer func() {
				let()
				wg.Wait()
				<-done
				_ = s.Close()
			}()
			core.SetSpoolFsync(s, func(*os.File) error {
				mu.Lock()
				first := !held
				held = true
				mu.Unlock()
				if first {
					close(entered)
					<-release
				}
				covered := maxSeqOnDisk(t, path)
				mu.Lock()
				syncs++
				coveredAt = append(coveredAt, covered)
				mu.Unlock()
				return nil
			})

			// Each sync append records how many fsyncs had completed when it
			// returned. The journal later says which seq it was.
			type ret struct {
				detail string
				syncs  int
			}
			rets := make(chan ret, tc.sync)
			errs := make(chan error, tc.sync+tc.bestEffort)
			for i := 0; i < tc.sync; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					detail := fmt.Sprintf("sync-%d", i)
					err := s.Append(ctx, core.Sync, core.AuditRecord{Event: "park", Fence: f, Detail: detail})
					mu.Lock()
					n := syncs
					returned++
					mu.Unlock()
					errs <- err
					rets <- ret{detail, n}
				}(i)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no fsync started")
			}
			// With the first fsync held, best-effort appends must still
			// return and every sync append must have written its record.
			go func() {
				defer close(done)
				for i := 0; i < tc.bestEffort; i++ {
					errs <- s.Append(ctx, core.BestEffort, core.AuditRecord{Event: "clone", Fence: f, Detail: fmt.Sprintf("best-%d", i)})
				}
				for s.Seq() < uint64(tc.sync+tc.bestEffort) {
					time.Sleep(time.Millisecond)
				}
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("appends blocked behind an fsync in flight")
			}
			mu.Lock()
			early := returned
			mu.Unlock()
			if early != 0 {
				t.Fatalf("%d sync appends returned before any fsync completed", early)
			}
			let()
			wg.Wait()
			close(errs)
			close(rets)
			for err := range errs {
				if err != nil {
					t.Fatalf("Append: %v", err)
				}
			}

			mu.Lock()
			gotSyncs, covered := syncs, slices.Clone(coveredAt)
			mu.Unlock()
			if gotSyncs < 1 || gotSyncs > tc.wantSyncs {
				t.Fatalf("fsyncs = %d, want 1..%d for %d sync appends", gotSyncs, tc.wantSyncs, tc.sync)
			}
			seqOf := journalSeqByDetail(t, dir)
			for r := range rets {
				seq, ok := seqOf[r.detail]
				if !ok {
					t.Fatalf("%s is not in the journal", r.detail)
				}
				if r.syncs == 0 || covered[r.syncs-1] < seq {
					t.Fatalf("%s (seq %d) returned after %d fsyncs covering up to seq %v: not durable", r.detail, seq, r.syncs, covered[:r.syncs])
				}
			}
			want := make([]uint64, 0, tc.sync+tc.bestEffort)
			for i := 1; i <= tc.sync+tc.bestEffort; i++ {
				want = append(want, uint64(i))
			}
			if seqs := journalSeqs(t, dir); !slices.Equal(seqs, want) {
				t.Fatalf("seqs = %v, want %v", seqs, want)
			}
			if _, err := core.VerifySpool(path, nil); err != nil {
				t.Fatalf("VerifySpool: %v", err)
			}
		})
	}
}

// TestSpoolClose checks that appends racing Close land before it or fail
// with ErrAudit. An append after Close fails, a second Close fails, and
// what was written still verifies. Run with -race.
func TestSpoolClose(t *testing.T) {
	cases := []struct {
		name string
		dur  core.Durability
	}{
		{name: "best-effort appends racing close", dur: core.BestEffort},
		{name: "sync appends racing close", dur: core.Sync},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := core.OpenSpool(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						if err := s.Append(ctx, tc.dur, core.AuditRecord{Event: "clone", Fence: f}); err != nil {
							return
						}
					}
				}()
			}
			for s.Seq() < 64 {
				time.Sleep(time.Millisecond)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			wg.Wait()
			if err := s.Append(ctx, tc.dur, core.AuditRecord{Event: "clone", Fence: f}); !errors.Is(err, core.ErrAudit) {
				t.Fatalf("Append after Close = %v, want ErrAudit", err)
			}
			if err := s.Close(); err == nil {
				t.Fatal("a second Close succeeded")
			}
			if _, err := core.VerifySpool(filepath.Join(dir, "audit.jsonl"), nil); err != nil {
				t.Fatalf("VerifySpool: %v", err)
			}
		})
	}
}

// maxSeqOnDisk is the largest sequence number of a readable line in the
// spool, as an fsync in flight would make it durable.
func maxSeqOnDisk(t *testing.T, path string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	for _, l := range strings.Split(string(b), "\n") {
		var r core.AuditRecord
		if json.Unmarshal([]byte(l), &r) == nil {
			seq = max(seq, r.Seq)
		}
	}
	return seq
}

// journalSeqByDetail maps each record's Detail to its sequence number.
func journalSeqByDetail(t *testing.T, dir string) map[string]uint64 {
	t.Helper()
	fh, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	out := map[string]uint64{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r core.AuditRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Detail != "" {
			out[r.Detail] = r.Seq
		}
	}
	return out
}

func summary(r core.SpoolReport) string {
	gaps := []string{}
	for _, g := range r.Gaps {
		lost := "-"
		if g.Lost != nil {
			lost = fmt.Sprintf("%d-%d", g.Lost.From, g.Lost.To)
		}
		gaps = append(gaps, fmt.Sprintf("%d:%s", g.Seq, lost))
	}
	return fmt.Sprintf("records=%d unchained=%d checkpoints=%d signed=%d unsigned=%d torn=%v gaps=%v",
		r.Records, r.Unchained, r.Checkpoints, r.SignedSeq, r.Unsigned, r.TornTail, gaps)
}

// rechain recomputes every record's prev_hash and hash, as someone who can
// edit the spool but has no checkpoint key would.
func rechain(t *testing.T, lines []string) []string {
	t.Helper()
	prev := ""
	for i, l := range lines {
		var r core.AuditRecord
		if json.Unmarshal([]byte(l), &r) != nil {
			continue
		}
		r.PrevHash, r.Hash = prev, ""
		b, _ := json.Marshal(r)
		sum := sha256.Sum256(b)
		r.Hash = hex.EncodeToString(sum[:])
		b, _ = json.Marshal(r)
		lines[i], prev = string(b), r.Hash
	}
	return lines
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// journalSeqs reads the sequence numbers of the spool's on-disk journal,
// skipping lines that are not records.
func journalSeqs(t *testing.T, dir string) []uint64 {
	t.Helper()
	fh, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var seqs []uint64
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r core.AuditRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			seqs = append(seqs, r.Seq)
		}
	}
	return seqs
}

// TestOpenSpool checks that a spool opens fresh in an empty directory and
// refuses a directory that is not there or a path it cannot write.
func TestOpenSpool(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, dir string) string // returns the directory to open
		wantErr bool
	}{
		{name: "an empty directory opens at seq 0", prepare: func(_ *testing.T, dir string) string { return dir }},
		{name: "a directory that is not there does not open", wantErr: true,
			prepare: func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing") }},
		{name: "a spool path that is a directory does not open", wantErr: true, prepare: func(t *testing.T, dir string) string {
			if err := os.Mkdir(filepath.Join(dir, "audit.jsonl"), 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := core.OpenSpool(tc.prepare(t, t.TempDir()), nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("OpenSpool = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			defer func() { _ = s.Close() }()
			if s.Seq() != 0 {
				t.Fatalf("seq = %d, want 0", s.Seq())
			}
		})
	}
}

// TestSpoolGaps checks that writes failing in a row leave one gap naming
// every sequence number they lost, the failed gap records' own included.
// A record that cannot be encoded is lost the same way. The spool still
// verifies.
func TestSpoolGaps(t *testing.T) {
	cases := []struct {
		name       string
		failures   int  // appends whose write fails
		badTime    bool // the failing append's time has no JSON form instead
		wantSeqs   []uint64
		wantReport string
	}{
		{name: "one failed write", failures: 1, wantSeqs: []uint64{1, 3, 4},
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[3:2-2]"},
		{name: "two failed writes, the gap between them failing too", failures: 2, wantSeqs: []uint64{1, 5, 6},
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[5:2-4]"},
		{name: "three failed writes", failures: 3, wantSeqs: []uint64{1, 7, 8},
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[7:2-6]"},
		{name: "a record that cannot be encoded", failures: 1, badTime: true, wantSeqs: []uint64{1, 3, 4},
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[3:2-2]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			s, err := core.OpenSpool(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			f := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
			if err := s.Append(ctx, core.Sync, core.AuditRecord{Event: "clone", Fence: f}); err != nil {
				t.Fatal(err)
			}
			// A read-only handle makes every write fail until the spool's
			// own file is put back.
			var old *os.File
			if !tc.badTime {
				ro, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ro.Close() }()
				old = core.SwapSpoolFile(s, ro)
			}
			for range tc.failures {
				rec := core.AuditRecord{Event: "park", Fence: f}
				if tc.badTime {
					rec.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
				}
				if err := s.Append(ctx, core.Sync, rec); !errors.Is(err, core.ErrAudit) {
					t.Fatalf("failing Append = %v, want ErrAudit", err)
				}
			}
			if old != nil {
				core.SwapSpoolFile(s, old)
			}
			if err := s.Append(ctx, core.Sync, core.AuditRecord{Event: "attach", Fence: f}); err != nil {
				t.Fatalf("Append after the failures = %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if seqs := journalSeqs(t, dir); !slices.Equal(seqs, tc.wantSeqs) {
				t.Fatalf("seqs = %v, want %v", seqs, tc.wantSeqs)
			}
			rep, err := core.VerifySpool(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := summary(rep); got != tc.wantReport {
				t.Fatalf("report = %s, want %s", got, tc.wantReport)
			}
		})
	}
}

// TestSpoolCheckpointInterval checks that a zero interval means a
// checkpoint every DefaultCheckpointEvery records, and that Close signs
// what the last checkpoint does not cover. A closing checkpoint that cannot
// be written leaves the tail unsigned, and the spool still verifies.
func TestSpoolCheckpointInterval(t *testing.T) {
	cases := []struct {
		name       string
		records    int
		failClose  bool // the closing checkpoint's write fails
		wantReport string
	}{
		{name: "a zero interval signs every 256 records", records: core.DefaultCheckpointEvery,
			wantReport: "records=257 unchained=0 checkpoints=1 signed=257 unsigned=0 torn=false gaps=[]"},
		{name: "close signs the records after the last checkpoint", records: 3,
			wantReport: "records=4 unchained=0 checkpoints=1 signed=4 unsigned=0 torn=false gaps=[]"},
		{name: "a closing checkpoint that cannot be written leaves the tail unsigned", records: 3, failClose: true,
			wantReport: "records=3 unchained=0 checkpoints=0 signed=0 unsigned=3 torn=false gaps=[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			s, err := core.OpenSpool(dir, &core.Checkpoints{KeyID: "k", Key: priv})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			for range tc.records {
				if err := s.Append(ctx, core.BestEffort, core.AuditRecord{Event: "clone"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.failClose {
				ro, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				old := core.SwapSpoolFile(s, ro)
				defer func() { _ = old.Close() }()
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close = %v", err)
			}
			rep, err := core.VerifySpool(path, map[string]ed25519.PublicKey{"k": pub})
			if err != nil {
				t.Fatal(err)
			}
			if got := summary(rep); got != tc.wantReport {
				t.Fatalf("report = %s, want %s", got, tc.wantReport)
			}
		})
	}
}
