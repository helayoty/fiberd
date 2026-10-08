package filelane_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/filelane"
)

// next waits for the lane's next event, or for it to close.
func next(t *testing.T, ch <-chan home.GrantEvent) (home.GrantEvent, bool) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		return ev, ok
	case <-time.After(10 * time.Second):
		t.Fatal("no event from the lane")
		return home.GrantEvent{}, false
	}
}

func TestPoll(t *testing.T) {
	cases := []struct {
		name  string
		every time.Duration
		files int // written before Poll starts
		// fill waits for the lane's buffer to fill before the context
		// ends, so the poller is blocked delivering when it does.
		fill bool
	}{
		{name: "a missing directory is created", every: time.Millisecond},
		{name: "the first scan delivers at once, at the default period", every: 0, files: 1},
		{name: "a fast period delivers too", every: time.Millisecond, files: 2},
		{name: "the lane closes while blocked on a full buffer", every: time.Millisecond, files: 20, fill: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "grants")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.files > 0 {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for i := range c.files {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("g%02d.jwt", i)), []byte(fmt.Sprint(i)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ch, err := filelane.Poll(ctx, dir, c.every)
			if err != nil {
				t.Fatal(err)
			}
			if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
				t.Fatalf("Poll left no directory at %s: %v", dir, err)
			}
			if c.fill {
				deadline := time.Now().Add(10 * time.Second)
				for len(ch) < cap(ch) {
					if time.Now().After(deadline) {
						t.Fatalf("the lane holds %d of %d events", len(ch), cap(ch))
					}
					time.Sleep(time.Millisecond)
				}
			} else {
				for i := range c.files {
					ev, ok := next(t, ch)
					if want := fmt.Sprint(i); !ok || ev.Kind != home.GrantAdded || string(ev.Token) != want {
						t.Fatalf("event %d = %+v (open %v), want the token %q", i, ev, ok, want)
					}
				}
			}
			cancel()
			// The lane closes once the context ends. A full lane still
			// holds what it had, in order and never past the files.
			last := -1
			for {
				ev, ok := next(t, ch)
				if !ok {
					break
				}
				var i int
				if _, err := fmt.Sscan(string(ev.Token), &i); err != nil || !c.fill || i <= last || i >= c.files {
					t.Fatalf("unexpected event %+v after the files were delivered", ev)
				}
				last = i
			}
		})
	}
}

func TestPollRefusesAnUnusableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		dir  string
	}{
		{name: "a path through a regular file", dir: filepath.Join(file, "grants")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch, err := filelane.Poll(context.Background(), c.dir, time.Millisecond)
			if err == nil || ch != nil {
				t.Fatalf("Poll(%s) = %v, %v; want an error and no lane", c.dir, ch, err)
			}
		})
	}
}
