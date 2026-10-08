package filelane

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
)

func mint(t *testing.T, uid string) string {
	t.Helper()
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := (&grant.Issuer{Key: key, URL: "https://issuer.test"}).Mint(core.Grant{UID: uid, Audience: "node", LeaseExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestScan drives one lane's scans by hand, in order, so each step sees
// exactly one scan of what the previous steps left.
func TestScan(t *testing.T) {
	dir := t.TempDir()
	tokA, tokB := mint(t, "uid-a"), mint(t, "uid-b")
	seen := map[string]fileState{}
	write := func(name, body string) func(t *testing.T) {
		return func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	remove := func(name string) func(t *testing.T) {
		return func(t *testing.T) {
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	added := func(tok string) home.GrantEvent { return home.GrantEvent{Kind: home.GrantAdded, Token: []byte(tok)} }
	removed := func(uid string) home.GrantEvent { return home.GrantEvent{Kind: home.GrantRemoved, UID: uid} }

	steps := []struct {
		name   string
		change func(t *testing.T)
		want   []home.GrantEvent
	}{
		{name: "an empty directory delivers nothing"},
		{name: "only *.jwt files are grants, delivered in name order", change: func(t *testing.T) {
			write("b.jwt", tokB)(t)
			write("a.jwt", tokA)(t)
			write("notes.txt", "ignored")(t)
			write("junk.jwt", "not a token")(t)
			if err := os.Mkdir(filepath.Join(dir, "sub.jwt"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "dangling.jwt")); err != nil {
				t.Fatal(err)
			}
		}, want: []home.GrantEvent{added(tokA), added(tokB), added("not a token")}},
		{name: "unchanged files are not delivered again"},
		// Reading a FIFO blocks until a writer comes, which would stall
		// the lane for every other grant.
		{name: "a named pipe is not a grant", change: func(t *testing.T) {
			if err := syscall.Mkfifo(filepath.Join(dir, "pipe.jwt"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a rewritten file is delivered again", change: write("a.jwt", tokA+"\n"),
			want: []home.GrantEvent{added(tokA + "\n")}},
		{name: "a removed file names the UID its token carried", change: remove("b.jwt"),
			want: []home.GrantEvent{removed("uid-b")}},
		{name: "a removed file whose token had no UID delivers nothing", change: remove("junk.jwt")},
		{name: "a directory that cannot be read removes nothing", change: func(t *testing.T) {
			remove("")(t)
		}},
		{name: "once it reads again, what is gone is removed", change: func(t *testing.T) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: []home.GrantEvent{removed("uid-a")}},
	}
	for _, st := range steps {
		ok := t.Run(st.name, func(t *testing.T) {
			if st.change != nil {
				st.change(t)
			}
			ch := make(chan home.GrantEvent, 16)
			done := make(chan struct{})
			go func() { defer close(ch); defer close(done); scan(context.Background(), dir, seen, ch) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("scan blocks")
			}
			var got []home.GrantEvent
			for ev := range ch {
				got = append(got, ev)
			}
			if !slices.EqualFunc(got, st.want, func(a, b home.GrantEvent) bool {
				return a.Kind == b.Kind && a.UID == b.UID && string(a.Token) == string(b.Token)
			}) {
				t.Fatalf("events %+v, want %+v", got, st.want)
			}
		})
		if !ok {
			return // later steps build on this one
		}
	}
}

// TestScanStopsWithContext checks that a scan blocked on a full lane
// returns once the context ends, for additions and removals alike.
func TestScanStopsWithContext(t *testing.T) {
	cases := []struct {
		name string
		seen map[string]fileState // what an earlier scan saw
		file bool                 // a.jwt exists now
	}{
		{name: "blocked delivering an addition", file: true, seen: map[string]fileState{}},
		{name: "blocked delivering a removal", seen: map[string]fileState{"gone.jwt": {uid: "uid-gone"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.file {
				if err := os.WriteFile(filepath.Join(dir, "a.jwt"), []byte(mint(t, "uid-a")), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			ch := make(chan home.GrantEvent) // nobody reads, so every send blocks
			done := make(chan struct{})
			go func() { defer close(done); scan(ctx, dir, c.seen, ch) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("scan did not return after its context ended")
			}
		})
	}
}
