//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// permOf is the permission bits of path, following a link, 0 when it
// cannot be read.
func permOf(path string) os.FileMode {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

// TestStoreModes checks that the stores of template memory in the clear
// are fiberd's alone. Regression: parents/ and zygote-images/ were 0755,
// and a filed self-checkpoint kept criu's 0644 files. A self-checkpoint
// that is not filed is removed (regression: it stayed in zygote-images).
func TestStoreModes(t *testing.T) {
	grant := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name string
		be   func() *codecBackend
		// before runs on the config before New.
		before func(t *testing.T, c *Config)
		// want maps a path under the template cache to its mode, 0 for absent.
		want func(r *Runtime) map[string]os.FileMode
	}{
		{name: "New makes both stores 0700, also when an earlier fiberd left them 0755",
			before: func(t *testing.T, c *Config) {
				for _, d := range []string{"parents", "zygote-images"} {
					if err := os.MkdirAll(filepath.Join(c.TemplateCache, d), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Join(c.TemplateCache, d), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: func(r *Runtime) map[string]os.FileMode {
				return map[string]os.FileMode{r.parentsDir(): 0o700, r.zygoteImagesDir(): 0o700}
			}},
		{name: "a filed self-checkpoint is 0700 with 0600 files",
			want: func(r *Runtime) map[string]os.FileMode {
				entry := filepath.Join(r.parentsDir(), shaOf("zygote pages of g1"))
				return map[string]os.FileMode{r.parentsDir(): 0o700, r.zygoteImagesDir(): 0o700, entry: 0o700,
					filepath.Join(entry, fakePagesFile): 0o600, filepath.Join(r.zygoteImagesDir(), "g1"): 0}
			}},
		{name: "a self-checkpoint the codec cannot load is removed", be: func() *codecBackend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.failLoadAt = 1
			return cb
		}, want: func(r *Runtime) map[string]os.FileMode {
			return map[string]os.FileMode{filepath.Join(r.zygoteImagesDir(), "g1"): 0, filepath.Join(r.parentsDir(), shaOf("zygote pages of g1")): 0}
		}},
		{name: "what a failed self-checkpoint wrote is removed", be: func() *codecBackend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.err, cb.partial = errors.New("fake: dump failed"), true
			return cb
		}, want: func(r *Runtime) map[string]os.FileMode {
			return map[string]os.FileMode{filepath.Join(r.zygoteImagesDir(), "g1"): 0}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			if tc.be != nil {
				cb = tc.be()
			}
			r := newTestRuntime(t, cb, func(c *Config) {
				if tc.before != nil {
					tc.before(t, c)
				}
			})
			if err := r.PrepareTemplate(context.Background(), grant); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			for path, want := range tc.want(r) {
				if got := permOf(path); got != want {
					t.Errorf("%s mode %v, want %v", path, got, want)
				}
			}
		})
	}
}

// TestRegisterParentModes checks what filing does to modes. A moved
// self-checkpoint becomes fiberd's alone (regression: it kept 0755 and
// 0644). A linked artifact's images are not this store's to change.
func TestRegisterParentModes(t *testing.T) {
	cases := []struct {
		name      string
		move      bool
		wantEntry os.FileMode
		wantPages os.FileMode
	}{
		{name: "a self-checkpoint is moved and made owner-only", move: true, wantEntry: 0o700, wantPages: 0o600},
		{name: "an artifact's images are linked as they are", wantEntry: 0o755, wantPages: 0o644},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{cfg: Config{TemplateCache: t.TempDir()}, be: newCodecBackend(core.TierCheckpoint), parents: map[string]backend.Parent{}}
			src := filepath.Join(t.TempDir(), "images")
			if err := writeParentDir(src, "a"); err != nil {
				t.Fatal(err)
			}
			sha, err := r.registerParent(src, tc.move)
			if err != nil {
				t.Fatalf("registerParent: %v", err)
			}
			entry := filepath.Join(r.parentsDir(), sha)
			if got := permOf(r.parentsDir()); got != 0o700 {
				t.Errorf("store mode %v, want 0700", got)
			}
			if got := permOf(entry); got != tc.wantEntry {
				t.Errorf("entry mode %v, want %v", got, tc.wantEntry)
			}
			if got := permOf(filepath.Join(entry, fakePagesFile)); got != tc.wantPages {
				t.Errorf("pages mode %v, want %v", got, tc.wantPages)
			}
		})
	}
}

// storeHome is a runtime with a parent store and a delta store, and no
// cgroups, pruner or backend instance.
func storeHome(t *testing.T) (*Runtime, *codecBackend) {
	t.Helper()
	root := t.TempDir()
	cb := newCodecBackend(core.TierCheckpoint)
	r := &Runtime{cfg: Config{TemplateCache: filepath.Join(root, "cache"), DeltaDir: filepath.Join(root, "deltas")}, be: cb,
		parents: map[string]backend.Parent{}, warms: map[string]*warm{}}
	if err := os.MkdirAll(r.parentsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return r, cb
}

// cacheImages writes an artifact's unpacked images under r's template
// cache, in the directory of a digest made from pages, and returns it.
func cacheImages(t *testing.T, r *Runtime, pages string) string {
	t.Helper()
	images := filepath.Join(r.cfg.TemplateCache, shaOf("artifact "+pages), "images")
	if err := writeParentDir(images, pages); err != nil {
		t.Fatal(err)
	}
	return images
}

// fileEntry writes a parent checkpoint into r's store and returns its hash.
func fileEntry(t *testing.T, r *Runtime, pages string) string {
	t.Helper()
	sha := shaOf(pages)
	if err := writeParentDir(filepath.Join(r.parentsDir(), sha), pages); err != nil {
		t.Fatal(err)
	}
	return sha
}

// nameByDelta writes a delta manifest under r's delta store naming sha.
func nameByDelta(t *testing.T, r *Runtime, grant, name, sha string) {
	t.Helper()
	if err := writeDelta(r.cfg.DeltaDir, grant, name, sha); err != nil {
		t.Fatal(err)
	}
}

// writeDelta writes a delta manifest naming sha at deltas/grant/name.
func writeDelta(deltas, grant, name, sha string) error {
	dir := filepath.Join(deltas, grant, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "manifest.json"), manifest{Fence: grant + "/1-1", Delta: true, Parent: sha})
}

// pruned waits for a prune that found the store idle. The home's own
// pruner may hold the store for a moment.
func pruned(t *testing.T, r *Runtime) {
	t.Helper()
	waitFor(t, "a prune", r.pruneParents)
}

// TestPruneParents checks what a prune removes: every store entry no
// warm instance and no delta names, loaded or not, scratch directories a
// crash left, and author images under the template cache that no link
// names and no warm in the making holds (regression: a link went and the
// images it named stayed in the clear for good). What a link names
// outside the cache stays. Named entries and anything that is not a
// store entry stay. A busy store or an unreadable delta store removes
// nothing and asks to be tried again.
func TestPruneParents(t *testing.T) {
	cases := []struct {
		name string
		// setup fills the stores and returns the paths under the store
		// that must stay and those that must go.
		setup    func(t *testing.T, r *Runtime) (stay, gone []string)
		hold     bool // a section is open during the prune
		wantDone bool
	}{
		{name: "unnamed entries go, entries a warm or a delta names stay", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			warmed, parked, claimed, unnamed := fileEntry(t, r, "warm"), fileEntry(t, r, "parked"), fileEntry(t, r, "claimed"), fileEntry(t, r, "unnamed")
			r.warms["g1"] = &warm{grantUID: "g1", parentSHA: warmed}
			r.warms["g2"] = &warm{grantUID: "g2"} // without a parent
			nameByDelta(t, r, "g1", "1-1", parked)
			nameByDelta(t, r, "g3", "claimed-s-1", claimed)
			return []string{warmed, parked, claimed}, []string{unnamed}
		}},
		{name: "a loaded unnamed parent is closed and forgotten", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			sha := fileEntry(t, r, "loaded")
			if _, err := r.parent(sha); err != nil {
				t.Fatal(err)
			}
			return nil, []string{sha}
		}},
		{name: "a link goes, and so do the author images it names under the cache", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			images := cacheImages(t, r, "linked")
			if err := os.Symlink(images, filepath.Join(r.parentsDir(), shaOf("linked"))); err != nil {
				t.Fatal(err)
			}
			return []string{filepath.Dir(images)}, []string{shaOf("linked"), images}
		}},
		{name: "a link goes, what it names outside the cache stays", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			images := filepath.Join(t.TempDir(), "images")
			if err := writeParentDir(images, "linked"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(images, filepath.Join(r.parentsDir(), shaOf("linked"))); err != nil {
				t.Fatal(err)
			}
			return []string{images}, []string{shaOf("linked")}
		}},
		{name: "author images stay while a link names them or a warm in the making holds them", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			named, held, orphan := cacheImages(t, r, "named"), cacheImages(t, r, "held"), cacheImages(t, r, "orphan")
			if err := os.Symlink(named, filepath.Join(r.parentsDir(), shaOf("named"))); err != nil {
				t.Fatal(err)
			}
			r.warms["g1"] = &warm{grantUID: "g1", parentSHA: shaOf("named")}
			r.imagesHeld = map[string]int{held: 1}
			// Not an artifact's directory, so not the prune's to touch.
			stray := filepath.Join(r.cfg.TemplateCache, "notes", "images")
			if err := writeParentDir(stray, "stray"); err != nil {
				t.Fatal(err)
			}
			return []string{named, held, stray, shaOf("named")}, []string{orphan}
		}},
		{name: "scratch directories a crash left go, anything else stays", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			for _, d := range []string{".0123456789ab.pull-42", ".seal-7", "notes"} {
				if err := os.MkdirAll(filepath.Join(r.parentsDir(), d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(r.parentsDir(), "README"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"notes", "README"}, []string{".0123456789ab.pull-42", ".seal-7"}
		}},
		{name: "a delta whose manifest cannot be read names nothing", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			sha := fileEntry(t, r, "half written")
			write(t, filepath.Join(r.cfg.DeltaDir, "g1", "1-1"), map[string]string{"manifest.json": `{"parent_sha256": "` + sha[:10]})
			if err := os.WriteFile(filepath.Join(r.cfg.DeltaDir, "stray"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return nil, []string{sha}
		}},
		{name: "no delta store: only warms name parents", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			r.cfg.DeltaDir = filepath.Join(t.TempDir(), "none")
			warmed, unnamed := fileEntry(t, r, "warm"), fileEntry(t, r, "unnamed")
			r.warms["g1"] = &warm{grantUID: "g1", parentSHA: warmed}
			return []string{warmed}, []string{unnamed}
		}},
		{name: "an open section: nothing goes", hold: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			return []string{fileEntry(t, r, "unnamed")}, nil
		}},
		{name: "a delta store that cannot be listed: nothing goes", setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			r.cfg.DeltaDir = filepath.Join(r.parentsDir(), fileEntry(t, r, "under"), fakePagesFile)
			return []string{fileEntry(t, r, "unnamed")}, nil
		}},
		{name: "a grant's delta directory that cannot be listed: nothing goes", setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			if err := os.MkdirAll(r.cfg.DeltaDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(r.parentsDir(), fileEntry(t, r, "file"), fakePagesFile), filepath.Join(r.cfg.DeltaDir, "g1")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(r.cfg.DeltaDir, "g2"), 0o000); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() == 0 {
				t.Skip("root lists a 0000 directory")
			}
			return []string{fileEntry(t, r, "unnamed")}, nil
		}},
		{name: "no parent store", wantDone: true, setup: func(t *testing.T, r *Runtime) ([]string, []string) {
			r.cfg.TemplateCache = filepath.Join(t.TempDir(), "none")
			return nil, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, cb := storeHome(t)
			stay, gone := tc.setup(t, r)
			if tc.hold {
				done := r.useParents()
				defer done()
			}
			if got := r.pruneParents(); got != tc.wantDone {
				t.Fatalf("pruneParents = %v, want %v", got, tc.wantDone)
			}
			at := func(p string) string {
				if filepath.IsAbs(p) {
					return p
				}
				return filepath.Join(r.parentsDir(), p)
			}
			for _, p := range stay {
				if _, err := os.Lstat(at(p)); err != nil {
					t.Errorf("%s was removed: %v", p, err)
				}
			}
			for _, p := range gone {
				if _, err := os.Lstat(at(p)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s stayed: %v", p, err)
				}
				if _, ok := r.parents[p]; ok {
					t.Errorf("%s is still loaded", p)
				}
			}
			for _, p := range cb.loadedParents() {
				if _, kept := r.parents[p.sha]; kept == (p.closed.Load() == 1) {
					t.Errorf("parent %s kept %v, closed %d times", p.sha[:12], kept, p.closed.Load())
				}
			}
		})
	}
}

// TestPruneRacesWarms runs warms that file a parent and publish the warm
// naming it, parks that write a manifest naming a parent, and claims that
// find a parent or pull it again, against a prune that runs without end.
// A section that recorded its use must always find its parent after.
func TestPruneRacesWarms(t *testing.T) {
	cases := []struct {
		name   string
		rounds int
		users  int
	}{
		{name: "warms and parks against the prune", rounds: 100, users: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := storeHome(t)
			stop := make(chan struct{})
			var pruner sync.WaitGroup
			pruner.Add(1)
			go func() {
				defer pruner.Done()
				for {
					select {
					case <-stop:
						return
					default:
						r.pruneParents()
					}
				}
			}()
			errs := make(chan error, tc.users)
			var users sync.WaitGroup
			for u := range tc.users {
				users.Add(1)
				go func() {
					defer users.Done()
					grant := fmt.Sprintf("g%d", u)
					for i := range tc.rounds {
						// A warm: file the self-checkpoint and publish the warm.
						src := filepath.Join(t.TempDir(), "zygote-images")
						// Homes' warms share content, so filing meets entries
						// another user filed and the prune may be taking.
						if err := writeParentDir(src, fmt.Sprintf("round %d", i%3)); err != nil {
							errs <- err
							return
						}
						done := r.useParents()
						sha, err := r.registerParent(src, true)
						if err == nil {
							r.mu.Lock()
							r.warms[grant] = &warm{grantUID: grant, parentSHA: sha}
							r.mu.Unlock()
						}
						done()
						if err != nil {
							errs <- fmt.Errorf("%s round %d: registerParent: %w", grant, i, err)
							return
						}
						// A park: the delta's manifest names the warm's parent.
						done = r.useParents()
						_, err = r.parent(sha)
						if err == nil {
							err = writeDelta(r.cfg.DeltaDir, grant, fmt.Sprintf("1-%d", i), sha)
						}
						done()
						if err != nil {
							errs <- fmt.Errorf("%s round %d: the warm's parent is gone: %w", grant, i, err)
							return
						}
						// The warm ends. The delta still names the parent.
						r.mu.Lock()
						delete(r.warms, grant)
						r.mu.Unlock()
						done = r.useParents()
						_, err = r.parent(sha)
						done()
						if err != nil {
							errs <- fmt.Errorf("%s round %d: the delta's parent is gone: %w", grant, i, err)
							return
						}
						// The delta is discarded. Nothing names the parent.
						_ = os.RemoveAll(filepath.Join(r.cfg.DeltaDir, grant))
					}
				}()
			}
			users.Wait()
			close(stop)
			pruner.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if !r.pruneParents() {
				t.Fatal("the last prune found the store busy")
			}
			if ents, _ := os.ReadDir(r.parentsDir()); len(ents) != 0 {
				t.Fatalf("the store holds %d entries nothing names", len(ents))
			}
		})
	}
}

// TestPruneTriggers checks when a home prunes: at start, after a warm
// instance is dropped, and after a delta is discarded. A parked delta
// keeps its parent past its warm instance.
func TestPruneTriggers(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	parentOf := func(r *Runtime, pages string) string { return filepath.Join(r.parentsDir(), shaOf(pages)) }
	cases := []struct {
		name string
		mod  func(t *testing.T, c *Config)
		run  func(t *testing.T, r *Runtime)
	}{
		{name: "at start, what an earlier fiberd left that no delta names",
			mod: func(t *testing.T, c *Config) {
				for _, pages := range []string{"stale", "named"} {
					if err := writeParentDir(filepath.Join(c.TemplateCache, "parents", shaOf(pages)), pages); err != nil {
						t.Fatal(err)
					}
				}
				if err := writeDelta(c.DeltaDir, "g0", "1-1", shaOf("named")); err != nil {
					t.Fatal(err)
				}
			},
			run: func(t *testing.T, r *Runtime) {
				waitFor(t, "the start prune", func() bool { return !exists(parentOf(r, "stale")) })
				if !exists(parentOf(r, "named")) {
					t.Fatal("the start prune took a parent a delta names")
				}
			}},
		{name: "a dropped warm instance's parent goes", run: func(t *testing.T, r *Runtime) {
			if err := r.PrepareTemplate(context.Background(), g); err != nil {
				t.Fatal(err)
			}
			pruned(t, r)
			if !exists(parentOf(r, "zygote pages of g1")) {
				t.Fatal("a warm instance's parent was pruned")
			}
			r.DropTemplate("g1")
			waitFor(t, "the parent of the dropped warm instance to go", func() bool { return !exists(parentOf(r, "zygote pages of g1")) })
		}},
		{name: "a parked delta keeps its parent past its warm instance, and its discard lets it go", run: func(t *testing.T, r *Runtime) {
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}, CallerCert: callerDER})
			if err != nil {
				t.Fatal(err)
			}
			ref, err := r.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatal(err)
			}
			if m := readManifest(t, ref); !m.Delta || m.Parent != shaOf("zygote pages of g1") {
				t.Fatalf("manifest = %+v, want a delta over the warm's parent", m)
			}
			r.DropTemplate("g1")
			pruned(t, r)
			if !exists(parentOf(r, "zygote pages of g1")) {
				t.Fatal("the parent of a parked delta was pruned")
			}
			if err := r.Release(ctx, h.ID, true); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the parent of the discarded delta to go", func() bool { return !exists(parentOf(r, "zygote pages of g1")) })
		}},
		{name: "a delta discarded through DiscardDelta lets its parent go", run: func(t *testing.T, r *Runtime) {
			// Named before it is filed, since the home's pruner runs.
			nameByDelta(t, r, "g1", "claimed-s-1", shaOf("claimed"))
			sha := fileEntry(t, r, "claimed")
			pruned(t, r)
			if !exists(filepath.Join(r.parentsDir(), sha)) {
				t.Fatal("a claimed delta's parent was pruned")
			}
			if err := r.DiscardDelta(context.Background(), filepath.Join(r.cfg.DeltaDir, "g1", "claimed-s-1")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the parent of the discarded delta to go", func() bool { return !exists(filepath.Join(r.parentsDir(), sha)) })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, newCodecBackend(core.TierCheckpoint), func(c *Config) {
				if tc.mod != nil {
					tc.mod(t, c)
				}
			})
			tc.run(t, r)
		})
	}
}

// TestSweepStores checks what New removes of what a crash left in the
// clear: self-checkpoints never filed, an import's scratch directory
// under the delta store (with the parent it opened), a push's seal
// scratch beside a delta, and what an unpack of author images left
// beside the sealed tar. Regression: nothing swept them, so a home that
// crashed mid-warm, mid-import or mid-unpack kept template memory on
// disk until the same grant, delta or digest was used again. Deltas,
// their parents and the rest of the cache stay.
func TestSweepStores(t *testing.T) {
	hex := shaOf("artifact")
	cases := []struct {
		name string
		// leave writes a leftover before New and returns it.
		leave func(t *testing.T, c *Config) string
		stays bool
	}{
		{name: "a self-checkpoint never filed", leave: func(t *testing.T, c *Config) string {
			dir := filepath.Join(c.TemplateCache, "zygote-images", "g9")
			if err := writeParentDir(dir, "zygote pages of g9"); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{name: "an import's opened parent", leave: func(t *testing.T, c *Config) string {
			dir := filepath.Join(c.DeltaDir, ".import-123", "parent-open")
			if err := writeParentDir(dir, "imported"); err != nil {
				t.Fatal(err)
			}
			return filepath.Dir(dir)
		}},
		{name: "a push's seal scratch beside a delta", leave: func(t *testing.T, c *Config) string {
			dir := filepath.Join(c.DeltaDir, "g1", ".seal-7")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{name: "the opened tar of an unpack", leave: func(t *testing.T, c *Config) string {
			return writeLeftover(t, filepath.Join(c.TemplateCache, hex, "images.tar.open"))
		}},
		{name: "the tree an unpack verified", leave: func(t *testing.T, c *Config) string {
			dir := filepath.Join(c.TemplateCache, hex, "images.verified")
			if err := writeParentDir(dir, "verified"); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{name: "the tree an unpack replaced", leave: func(t *testing.T, c *Config) string {
			dir := filepath.Join(c.TemplateCache, hex, "images.old")
			if err := writeParentDir(dir, "old"); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{name: "a delta and its manifest stay", stays: true, leave: func(t *testing.T, c *Config) string {
			if err := writeDelta(c.DeltaDir, "g1", "1-1", shaOf("named")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(c.DeltaDir, "g1", "1-1", "manifest.json")
		}},
		{name: "a parent a delta names stays", stays: true, leave: func(t *testing.T, c *Config) string {
			if err := writeDelta(c.DeltaDir, "g1", "1-1", shaOf("named")); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(c.TemplateCache, "parents", shaOf("named"))
			if err := writeParentDir(dir, "named"); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{name: "a pulled artifact's config stays", stays: true, leave: func(t *testing.T, c *Config) string {
			return writeLeftover(t, filepath.Join(c.TemplateCache, hex, "config.json"))
		}},
		{name: "a file of another name under the delta store stays", stays: true, leave: func(t *testing.T, c *Config) string {
			return writeLeftover(t, filepath.Join(c.DeltaDir, "notes"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var left string
			newTestRuntime(t, newCodecBackend(core.TierCheckpoint), func(c *Config) { left = tc.leave(t, c) })
			if exists(left) != tc.stays {
				t.Fatalf("%s exists %v after New, want %v", left, !tc.stays, tc.stays)
			}
		})
	}
}

// writeLeftover writes an empty file at path, making its directory.
func writeLeftover(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
