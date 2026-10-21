//go:build linux

package host

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// The parent store holds template memory in the clear. It is owner-only,
// and pruned of every entry nothing on this home names any more.
//
//	<TemplateCache>/
//	  parents/            0700
//	    <sha>/            0700, files 0600 (a self-checkpoint or a pulled parent)
//	    <sha> -> images   a link to an artifact's unpacked images
//	    .<sha12>.pull-*   0700, one pull in flight (any name with a leading dot
//	                      is a section's scratch directory)
//	  zygote-images/      0700
//	    <grant>/          a self-checkpoint until it is filed under parents/
//	  <hex>/images/       0700, an artifact's author images, opened for a warm
//
// An entry is named by the parentSHA of a warm instance in r.warms, or
// by the manifest of a delta under DeltaDir (parked here, claimed from
// another home, or failed and kept for diagnosis). Everything else goes.
// Author images go when no store link names them and no warm in the
// making holds them (imagesHeld, under templateMu). A resolve unpacks
// them again.
//
// Every section of code that loads an entry, files one, or records a
// use of one (a warm published, a delta's manifest written) holds
// storeMu for reading, through useParents. The prune scans the names
// without the lock, then takes it for writing with TryLock and removes
// only when no section ended since the scan began. So it never removes
// an entry a section is about to use, never closes a parent a section
// holds, and never makes a section wait. A busy store is tried again.
//
//	section   RLock ── load / file / pull / push ── record the use ── uses++ ── RUnlock
//	prune     seen = uses ── scan names ── TryLock ── uses == seen ? remove : rescan ── Unlock

const (
	// pruneScans is how many scans a prune makes while sections keep
	// ending under it, before it waits pruneRetry.
	pruneScans = 3
	pruneRetry = time.Second
)

// ownerDir makes dir, and makes it fiberd's alone if it was there.
func ownerDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// ownerOnly makes every directory under dir 0700 and every file 0600. It
// follows no link. criu, runsc and a pull write theirs world-readable.
func ownerOnly(dir string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.Chmod(p, 0o700)
		case d.Type().IsRegular():
			return os.Chmod(p, 0o600)
		}
		return nil
	})
}

// zygoteImagesDir is where a warm instance's self-checkpoint is taken
// before it is filed in the parent store.
func (r *Runtime) zygoteImagesDir() string {
	return filepath.Join(r.cfg.TemplateCache, "zygote-images")
}

// useParents opens a section that may load, file or record a use of a
// parent store entry. The prune waits for none to be open. done ends it.
func (r *Runtime) useParents() (done func()) {
	r.storeMu.RLock()
	return func() {
		r.storeUses.Add(1)
		r.storeMu.RUnlock()
	}
}

// pokePrune asks the pruner for a prune. It never blocks, and pokes
// that arrive while one is pending are one prune.
func (r *Runtime) pokePrune() {
	if r.prune == nil {
		return
	}
	select {
	case r.prune <- struct{}{}:
	default:
	}
}

// pruneLoop runs prunes as they are asked for, and again after
// pruneRetry when a busy store put one off, until the runtime closes.
func (r *Runtime) pruneLoop() {
	defer close(r.pruneDone)
	var again <-chan time.Time
	for {
		select {
		case <-r.stop:
			return
		case <-r.prune:
		case <-again:
		}
		again = nil
		if !r.pruneParents() {
			again = time.After(pruneRetry)
		}
	}
}

// pruneParents removes every parent store entry that no warm instance
// and no delta names, and scratch directories a crash left. It reports
// false when it removed nothing because the store was busy or the
// names could not be read, so it is to be tried again.
func (r *Runtime) pruneParents() bool {
	for range pruneScans {
		seen := r.storeUses.Load()
		keep, err := r.namedParents()
		if err != nil {
			log.Printf("host: prune parents: %v", err)
			return false
		}
		if !r.storeMu.TryLock() {
			return false
		}
		if r.storeUses.Load() != seen {
			r.storeMu.Unlock()
			continue
		}
		r.removeUnnamed(keep)
		r.storeMu.Unlock()
		return true
	}
	return false
}

// namedParents is every parent hash a warm instance or a delta under
// DeltaDir names. A manifest that cannot be read names nothing. Every
// manifest that matters is written inside a section, or before one that
// finds its parent missing and pulls it again (ClaimDelta). A directory
// that cannot be listed is an error, since what it holds is unknown.
func (r *Runtime) namedParents() (map[string]bool, error) {
	keep := map[string]bool{}
	r.mu.Lock()
	for _, z := range r.warms {
		if z.parentSHA != "" {
			keep[z.parentSHA] = true
		}
	}
	r.mu.Unlock()
	grants, err := os.ReadDir(r.cfg.DeltaDir)
	if errors.Is(err, os.ErrNotExist) {
		return keep, nil
	}
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if !g.IsDir() {
			continue
		}
		deltas, err := os.ReadDir(filepath.Join(r.cfg.DeltaDir, g.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // discarded meanwhile
			}
			return nil, err
		}
		for _, d := range deltas {
			var m manifest
			if readJSON(filepath.Join(r.cfg.DeltaDir, g.Name(), d.Name(), "manifest.json"), &m) == nil && m.Parent != "" {
				keep[m.Parent] = true
			}
		}
	}
	return keep, nil
}

// removeUnnamed removes the store entries keep does not name, closing
// any that is loaded, and every scratch directory (a leading dot, such as
// a pull's), none of which is in use while the prune holds the store.
// Anything else is left alone. Then the author images no link names go
// (pruneImages).
func (r *Runtime) removeUnnamed(keep map[string]bool) {
	r.parentsMu.Lock()
	for sha, p := range r.parents {
		if !keep[sha] {
			p.Close()
			delete(r.parents, sha)
		}
	}
	r.parentsMu.Unlock()
	ents, err := os.ReadDir(r.parentsDir())
	if err != nil {
		return
	}
	var gone []string
	for _, e := range ents {
		name := e.Name()
		scratch := strings.HasPrefix(name, ".")
		if !scratch && (!isHex64(name) || keep[name]) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.parentsDir(), name)); err != nil {
			log.Printf("host: prune parent %s: %v", name, err)
			continue
		}
		if !scratch {
			gone = append(gone, name[:12])
		}
	}
	if len(gone) > 0 {
		log.Printf("host: pruned parent checkpoints %s", strings.Join(gone, " "))
	}
	r.pruneImages()
}

// pruneImages removes every <hex>/images under the template cache that
// no store link names and no warm in the making holds. The caller holds
// the store, so no link is made meanwhile, and templateMu is taken here
// so no resolve unpacks meanwhile. A resolve that runs after finds the
// images gone and unpacks them again.
func (r *Runtime) pruneImages() {
	r.templateMu.Lock()
	defer r.templateMu.Unlock()
	named := map[string]bool{}
	ents, _ := os.ReadDir(r.parentsDir())
	for _, e := range ents {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		if target, err := os.Readlink(filepath.Join(r.parentsDir(), e.Name())); err == nil {
			named[filepath.Clean(target)] = true
		}
	}
	caches, _ := os.ReadDir(r.cfg.TemplateCache)
	var gone []string
	for _, c := range caches {
		if !c.IsDir() || !isHex64(c.Name()) {
			continue
		}
		images := artifact.ImagesDir(filepath.Join(r.cfg.TemplateCache, c.Name()))
		if named[images] || r.imagesHeld[images] > 0 {
			continue
		}
		if _, err := os.Lstat(images); err != nil {
			continue
		}
		if err := os.RemoveAll(images); err != nil {
			log.Printf("host: prune images of template %s: %v", c.Name()[:12], err)
			continue
		}
		gone = append(gone, c.Name()[:12])
	}
	if len(gone) > 0 {
		log.Printf("host: pruned author images of templates %s", strings.Join(gone, " "))
	}
}

// releaseImages ends a warm's hold on the images its resolve unpacked.
func (r *Runtime) releaseImages(images string) {
	r.templateMu.Lock()
	if r.imagesHeld[images] > 1 {
		r.imagesHeld[images]--
	} else {
		delete(r.imagesHeld, images)
	}
	r.templateMu.Unlock()
}

// sweepStores removes what a crash left in the clear outside the parent
// store: self-checkpoints never filed (zygote-images/<grant>), an
// import's scratch directory under the delta store with its opened
// parent, a push's seal scratch beside a delta, and the opened tar and
// the trees an unpack of author images left beside the sealed one. It
// runs at start, before anything is served, so nothing is in use.
func (r *Runtime) sweepStores() {
	removeAll := func(dir string, keep func(name string) bool) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if keep != nil && keep(e.Name()) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				log.Printf("host: sweep %s: %v", filepath.Join(dir, e.Name()), err)
			}
		}
	}
	notScratch := func(name string) bool { return !strings.HasPrefix(name, ".") }
	removeAll(r.zygoteImagesDir(), nil)
	// No fiber outlives the fiberd that made its workspace, so every
	// tree there is a dead fiber's.
	removeAll(r.cfg.WorkspaceDir, nil)
	removeAll(r.cfg.DeltaDir, notScratch)
	grants, _ := os.ReadDir(r.cfg.DeltaDir)
	for _, g := range grants {
		if g.IsDir() {
			removeAll(filepath.Join(r.cfg.DeltaDir, g.Name()), notScratch)
		}
	}
	caches, _ := os.ReadDir(r.cfg.TemplateCache)
	for _, c := range caches {
		if !c.IsDir() || !isHex64(c.Name()) {
			continue
		}
		dir := filepath.Join(r.cfg.TemplateCache, c.Name())
		// What artifact.UnpackImages writes beside images/ and removes
		// when it ends.
		for _, p := range []string{"images.tar.open", "images.old", "images.verified"} {
			if err := os.RemoveAll(filepath.Join(dir, p)); err != nil {
				log.Printf("host: sweep %s: %v", filepath.Join(dir, p), err)
			}
		}
	}
}
