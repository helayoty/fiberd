// Package grantdir delivers grants to every file-fed home from a
// directory polled for *.jwt files. A new or changed file is GrantAdded
// with its contents; a removed file is GrantRemoved with the UID read
// (unverified: it is only used to stop admissions) from the last copy.
// An empty file is skipped until its token is written, so emptying a
// grant's file to rewrite it does not remove the grant.
// The standalone home points it at -grants-dir; the Kubernetes home at
// the Secret volume the issuer controller projects grants into.
package grantdir

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
)

// Poll returns grant events read from dir every `every`, until ctx ends. The
// directory is created if missing.
func Poll(ctx context.Context, dir string, every time.Duration) (<-chan home.GrantEvent, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if every <= 0 {
		every = 2 * time.Second
	}
	ch := make(chan home.GrantEvent, 16)
	go func() {
		defer close(ch)
		seen := map[string]fileState{}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			scan(ctx, dir, seen, ch)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return ch, nil
}

type fileState struct {
	mod  time.Time
	size int64
	uid  string
}

func scan(ctx context.Context, dir string, seen map[string]fileState, ch chan<- home.GrantEvent) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	present := map[string]bool{}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		// A projected volume lists its files as symlinks into ..data; a
		// plain directory as files. Both stat through to a regular file.
		if filepath.Ext(e.Name()) == ".jwt" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		// Reading a FIFO or a device could block the poll, and a file
		// over the token size limit is never a token, so neither is a
		// grant. Neither is read.
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > grant.MaxTokenBytes {
			continue
		}
		present[name] = true
		if st, ok := seen[name]; ok && st.mod.Equal(info.ModTime()) && st.size == info.Size() {
			continue
		}
		// A writer creates or truncates the file before it writes the
		// token, so an empty file is never a grant. It stays present,
		// so a grant being rewritten is not removed. It is not seen
		// either, so the poll that finds its bytes delivers them. A
		// file whose size changed while it was read is retried the
		// same way. A token only partly written can still be read. It
		// fails Verify, and once its size changes it is sent whole.
		if info.Size() == 0 {
			continue
		}
		tok, err := os.ReadFile(path)
		if err != nil || int64(len(tok)) != info.Size() {
			continue
		}
		uid, _ := grant.PeekUID(string(tok))
		seen[name] = fileState{mod: info.ModTime(), size: info.Size(), uid: uid}
		select {
		case ch <- home.GrantEvent{Kind: home.GrantAdded, Token: tok}:
		case <-ctx.Done():
			return
		}
	}
	for name, st := range seen {
		if present[name] {
			continue
		}
		delete(seen, name)
		if st.uid == "" {
			continue
		}
		select {
		case ch <- home.GrantEvent{Kind: home.GrantRemoved, UID: st.uid}:
		case <-ctx.Done():
			return
		}
	}
}
