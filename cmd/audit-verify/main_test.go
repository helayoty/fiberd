package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
)

// spoolOf writes a spool in dir. unchained is written before the spool
// is opened, then records are appended through core.Spool and it is
// closed, which checkpoints when cp is set. after is appended to the file
// once it is closed.
func spoolOf(t *testing.T, dir, unchained string, cp *core.Checkpoints, records int, after string) string {
	t.Helper()
	spool := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(spool, []byte(unchained), 0o600); err != nil {
		t.Fatal(err)
	}
	appendRecords(t, dir, cp, records)
	if after != "" {
		f, err := os.OpenFile(spool, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(after); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return spool
}

// appendRecords opens the spool in dir, appends n records and closes it.
func appendRecords(t *testing.T, dir string, cp *core.Checkpoints, n int) {
	t.Helper()
	s, err := core.OpenSpool(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := s.Append(context.Background(), core.BestEffort, core.AuditRecord{Event: "admit"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// chained hashes rec onto prev the way the spool does, as the SHA-256 of
// the record's JSON with Hash empty.
func chained(t *testing.T, rec core.AuditRecord, prev string) (core.AuditRecord, []byte) {
	t.Helper()
	rec.PrevHash, rec.Hash = prev, ""
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	rec.Hash = hex.EncodeToString(sum[:])
	if b, err = json.Marshal(rec); err != nil {
		t.Fatal(err)
	}
	return rec, append(b, '\n')
}

// lostSpool is a chain whose writes 2 and 3 failed, so seq 4 is the gap
// naming them, then a checkpointed record appended by the real spool.
func lostSpool(t *testing.T, dir string, cp *core.Checkpoints) string {
	t.Helper()
	at := time.Unix(1_700_000_000, 0).UTC()
	first, b1 := chained(t, core.AuditRecord{Seq: 1, Time: at, Event: "admit"}, "")
	_, b2 := chained(t, core.AuditRecord{Seq: 4, Time: at, Event: core.EventGap, Lost: &core.SeqRange{From: 2, To: 3}, Detail: "disk full"}, first.Hash)
	return spoolOf(t, dir, string(b1)+string(b2), cp, 1, "")
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A spool passes only when it verifies and a checkpoint covers it. The
// report names every gap and a torn tail. One that was never signed, has
// records before its chain started, or does not verify fails, and so does
// a trust file that names no Ed25519 key.
func TestRun(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp := &core.Checkpoints{KeyID: "audit-1", Key: priv}
	trustKey := jose.JSONWebKey{Key: pub, KeyID: "audit-1"}

	cases := []struct {
		name string
		// spool builds the spool in dir and returns its path.
		spool func(t *testing.T, dir string) string
		trust any // written as the -trust file, nil for no -trust
		args  []string
		want  int
		// wantOut and wantErr are substrings of stdout and stderr.
		wantOut []string
		wantErr string
	}{
		{name: "signed and checkpointed",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 3, "") },
			trust: trustKey, want: 0,
			wantOut: []string{": 4 chained records, 1 checkpoints; signed through seq 4, 0 records after it\n"}},
		{name: "empty",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 0, "") },
			trust: trustKey, want: 0, wantOut: []string{": 0 chained records, 0 checkpoints"}},
		{name: "no checkpoints",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", nil, 3, "") },
			trust: trustKey, want: 1, wantErr: "no checkpoint, so nothing in it is signed"},
		{name: "records before the chain started",
			spool: func(t *testing.T, dir string) string {
				return spoolOf(t, dir, `{"seq":1,"event":"admit"}`+"\n", cp, 3, "")
			},
			trust: trustKey, want: 1,
			wantOut: []string{"1 records before the chain started are not covered"},
			wantErr: "1 records are not chained"},
		{name: "a torn last line is reported and still passes",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 2, `{"seq":4,"ev`) },
			trust: trustKey, want: 0, wantOut: []string{"the last line is unreadable"}},
		{name: "a torn line the home has since covered names its gap",
			spool: func(t *testing.T, dir string) string {
				p := spoolOf(t, dir, "", cp, 2, `{"seq":4,"ev`)
				appendRecords(t, dir, cp, 1)
				return p
			},
			trust: trustKey, want: 0, wantOut: []string{"gap at seq 4: unreadable line at offset"}},
		{name: "records that were never written are named by their gap",
			spool: func(t *testing.T, dir string) string { return lostSpool(t, dir, cp) },
			trust: trustKey, want: 0, wantOut: []string{"gap at seq 4: seq 2-3 not written: disk full"}},
		{name: "an edited record fails",
			spool: func(t *testing.T, dir string) string {
				p := spoolOf(t, dir, "", cp, 2, "")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, bytes.Replace(b, []byte(`"admit"`), []byte(`"clone"`), 1), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			trust: trustKey, want: 1, wantErr: "the hash does not match the record"},
		{name: "a checkpoint by an untrusted key fails",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 1, "") },
			trust: jose.JSONWebKey{Key: otherPub, KeyID: "audit-2"}, want: 1, wantErr: `signer "audit-1" is not trusted`},
		{name: "a JWKS holding the key passes",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 1, "") },
			trust: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: otherPub, KeyID: "audit-2"}, trustKey}}, want: 0},
		{name: "the home's private key is trusted for its public half",
			spool: func(t *testing.T, dir string) string { return spoolOf(t, dir, "", cp, 1, "") },
			trust: jose.JSONWebKey{Key: priv, KeyID: "audit-1"}, want: 0},
		{name: "a missing spool fails",
			spool: func(_ *testing.T, dir string) string { return filepath.Join(dir, "nope.jsonl") },
			trust: trustKey, want: 1, wantErr: "no such file"},
		{name: "no -trust fails", want: 1, wantErr: "-trust is required"},
		{name: "a missing trust file fails", args: []string{"-trust", "/nonexistent/trust.json"}, want: 1, wantErr: "no such file"},
		{name: "a trust file that is not JSON fails", trust: "not json", want: 1, wantErr: "neither a JWK nor a JWKS"},
		{name: "a trust key that is not Ed25519 fails", trust: jose.JSONWebKey{Key: &ec.PublicKey, KeyID: "ec"},
			want: 1, wantErr: `key "ec" is not an Ed25519 key with a kid`},
		{name: "a trust key without a kid fails", trust: jose.JSONWebKey{Key: pub},
			want: 1, wantErr: "is not an Ed25519 key with a kid"},
		{name: "an unknown flag is a usage error", args: []string{"-bogus"}, want: 2, wantErr: "flag provided but not defined: -bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := tc.args
			if tc.spool != nil {
				args = append(args, "-spool", tc.spool(t, dir))
			}
			if tc.trust != nil {
				trust := filepath.Join(dir, "trust.json")
				if s, ok := tc.trust.(string); ok {
					if err := os.WriteFile(trust, []byte(s), 0o600); err != nil {
						t.Fatal(err)
					}
				} else {
					writeJSON(t, trust, tc.trust)
				}
				args = append(args, "-trust", trust)
			}
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tc.want, stdout.String(), stderr.String())
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(stdout.String(), w) {
					t.Fatalf("stdout = %q, want it to contain %q", stdout.String(), w)
				}
			}
			if !strings.Contains(stderr.String(), tc.wantErr) || (tc.wantErr == "") != (stderr.Len() == 0) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tc.wantErr)
			}
		})
	}
}
