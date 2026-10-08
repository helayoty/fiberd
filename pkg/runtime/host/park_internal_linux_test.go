//go:build linux

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// parkFixture is a runtime with one prepared grant and one running fiber,
// as every park and resume test starts from.
type parkFixture struct {
	r     *Runtime
	be    backend.Backend
	g     core.Grant
	h     core.FiberHandle
	fence core.Fence
}

func (f *parkFixture) fake() *fakeBackend {
	return f.be.(interface{ base() *fakeBackend }).base()
}

func (b *fakeBackend) base() *fakeBackend { return b }

func newParkFixture(t *testing.T, be backend.Backend, g core.Grant, mod func(*Config)) *parkFixture {
	t.Helper()
	r := newTestRuntime(t, be, mod)
	ctx := context.Background()
	if err := r.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("PrepareTemplate: %v", err)
	}
	fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
	h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return &parkFixture{r: r, be: be, g: g, h: h, fence: fence}
}

// imageBytesOf is what a parked directory weighed before its manifest
// was written beside the images.
func imageBytesOf(t *testing.T, ref string) uint64 {
	t.Helper()
	st, err := os.Stat(filepath.Join(ref, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return dirBytes(ref) - uint64(st.Size())
}

// fiberFlags reads a known fiber's park bookkeeping.
func (f *parkFixture) fiberFlags(t *testing.T, id string) (released, parked bool) {
	t.Helper()
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	fb, ok := f.r.fibers[id]
	if !ok {
		t.Fatalf("fiber %s is not running", id)
	}
	return fb.released, fb.parked
}

// TestPark checks that a park is a delta over the template's checkpoint when
// the backend has a codec and a parent, a full image otherwise. What is
// refused leaves the fiber running.
func TestPark(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name  string
		be    func() backend.Backend
		grant core.Grant
		mod   func(*Config)
		// before runs with the fiber running, before the park.
		before func(t *testing.T, f *parkFixture)
		sync   bool
		ctx    func() context.Context
		// wantErr is matched with errors.Is, errText as a fragment.
		wantErr error
		errText string
		// wantRef is whether the returned ref must be the delta dir even
		// on error.
		wantRef bool
		check   func(t *testing.T, f *parkFixture, ref string)
	}{
		{name: "async park: a delta over the self-checkpoint, no exit reported", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if ref != filepath.Join(f.r.cfg.DeltaDir, "g1", "1-1") {
					t.Fatalf("ref = %s", ref)
				}
				m := readManifest(t, ref)
				parent := shaOf("zygote pages of g1")
				if m.Fence != "g1/1/1" || m.GrantUID != "g1" || m.Endpoint != f.h.Endpoint || m.Handoff || m.Template != "sha256:tmpl" ||
					m.Backend != "fake" || !m.Delta || m.Parent != parent || m.WBytes != 7 {
					t.Fatalf("manifest = %+v", m)
				}
				if _, err := time.Parse(time.RFC3339Nano, m.ParkedAt); err != nil {
					t.Fatalf("parked_at %q: %v", m.ParkedAt, err)
				}
				if parks := f.fake().parked(); len(parks) != 1 || parks[0] != (backend.ParkSpec{Dir: ref, Sync: false}) {
					t.Fatalf("backend parks = %+v", parks)
				}
				if !f.r.HasDelta(ref) || !exists(filepath.Join(ref, fakeDeltaFile)) {
					t.Fatal("the delta is not there")
				}
				noExit(t, f.r)
				if f.r.root.Child("g1").Child("f-1-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the parked fiber's leaf or record remains")
				}
				if len(f.fake().killedIDs()) != 0 {
					t.Fatal("an async park must not kill the fiber: the checkpoint ends it")
				}
			}},
		{name: "sync park: the images are durable, then the fiber is killed", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g, sync: true,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if parks := f.fake().parked(); len(parks) != 1 || !parks[0].Sync {
					t.Fatalf("backend parks = %+v", parks)
				}
				if strings.Join(f.fake().killedIDs(), ",") != "g1/1/1" {
					t.Fatalf("killed %v", f.fake().killedIDs())
				}
				if m := readManifest(t, ref); !m.Delta {
					t.Fatalf("manifest = %+v", m)
				}
				noExit(t, f.r)
			}},
		{name: "below the checkpoint tier", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g,
			errText: "park needs FIBER_CHECKPOINT (backend fake offers FIBER_WARM)",
			check: func(t *testing.T, f *parkFixture, _ string) {
				if released, _ := f.fiberFlags(t, "g1/1/1"); released {
					t.Fatal("the fiber was marked released")
				}
			}},
		{name: "a backend without a codec parks a full image", be: func() backend.Backend { return newFakeBackend(core.TierCheckpoint) }, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				m := readManifest(t, ref)
				if m.Delta || m.Parent != "" || m.WBytes == 0 || m.WBytes != imageBytesOf(t, ref) {
					t.Fatalf("manifest = %+v, images weigh %d bytes", m, imageBytesOf(t, ref))
				}
			}},
		{name: "the codec's image size is the full image's weight when there is no parent", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.err = errors.New("fake: no criu")
			cb.imageBytes = 999
			return cb
		}, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta || m.WBytes != 999 {
					t.Fatalf("manifest = %+v", m)
				}
			}},
		{name: "a delta that cannot be computed keeps the full image", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.computeErr = errors.New("fake: pages differ")
			cb.imageErr = errors.New("fake: unreadable")
			return cb
		}, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta || m.Parent != "" || m.WBytes != imageBytesOf(t, ref) {
					t.Fatalf("manifest = %+v, images weigh %d bytes", m, imageBytesOf(t, ref))
				}
			}},
		{name: "a parent gone from the store keeps the full image", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before: func(t *testing.T, f *parkFixture) {
				sha := f.r.warmOf("g1").parentSHA
				f.r.parentsMu.Lock()
				delete(f.r.parents, sha)
				f.r.parentsMu.Unlock()
				if err := os.RemoveAll(filepath.Join(f.r.parentsDir(), sha)); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta {
					t.Fatalf("manifest = %+v", m)
				}
			}},
		{name: "an unknown fiber", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before:  func(t *testing.T, f *parkFixture) { f.h.ID = "g1/7/7" },
			errText: `unknown fiber "g1/7/7"`},
		{name: "a fiber whose id is no fence", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before: func(t *testing.T, f *parkFixture) {
				f.r.mu.Lock()
				f.r.fibers["odd"] = &fiber{id: "odd", grantUID: "g1", done: make(chan struct{})}
				f.r.mu.Unlock()
				f.h.ID = "odd"
			},
			errText: "want grant/epoch/seq"},
		{name: "a dump the backend refuses leaves the fiber running and the log for diagnosis", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkErr = errors.New("fake: criu dump failed")
			return cb
		}, grant: g, errText: "criu dump failed",
			check: func(t *testing.T, f *parkFixture, _ string) {
				dir := f.r.deltaDir(f.fence)
				if exists(dir) || !exists(filepath.Join(dir+".failed", "dump.log")) {
					t.Fatalf("delta dir exists %v, failed log kept %v", exists(dir), exists(filepath.Join(dir+".failed", "dump.log")))
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if err := f.r.Release(context.Background(), "g1/1/1", false); err != nil {
					t.Fatalf("release after a failed park: %v", err)
				}
			}},
		{name: "a sync park whose images cannot be made durable leaves the fiber running", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkDangling = true
			return cb
		}, grant: g, sync: true, wantErr: os.ErrNotExist,
			check: func(t *testing.T, f *parkFixture, _ string) {
				dir := f.r.deltaDir(f.fence)
				if exists(dir) || !exists(dir+".failed") {
					t.Fatal("the failed images must be set aside")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if len(f.fake().killedIDs()) != 0 {
					t.Fatal("the fiber was killed although its images are not durable")
				}
			}},
		{name: "over the grant's delta quota: refused before the dump", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: mib},
			before: func(t *testing.T, f *parkFixture) {
				// An earlier park of this grant, 5 MiB in its own delta
				// directory, against a quota of 4 x 1 x 1 MiB.
				write(t, filepath.Join(f.r.cfg.DeltaDir, "g1", "0-9"), map[string]string{"pages-1.img": strings.Repeat("x", 5*mib)})
			},
			wantErr: core.ErrDeltaQuota, errText: "holds 5242880 bytes",
			check: func(t *testing.T, f *parkFixture, _ string) {
				if len(f.fake().parked()) != 0 {
					t.Fatal("the backend was asked to dump")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if exists(f.r.deltaDir(f.fence)) {
					t.Fatal("a refused park left a delta directory")
				}
			}},
		{name: "within the quota: an earlier park counts, the dump proceeds", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: mib},
			before: func(t *testing.T, f *parkFixture) {
				write(t, filepath.Join(f.r.cfg.DeltaDir, "g1", "0-9"), map[string]string{"pages-1.img": strings.Repeat("x", 4*mib-100)})
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if len(f.fake().parked()) != 1 || !f.r.HasDelta(ref) {
					t.Fatal("the park did not happen")
				}
			}},
		{name: "a device slice is evicted before the checkpoint, even when the engine complains", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.evictErr = errors.New("fake: engine busy")
			return sb
		}, grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib, DeviceBudget: core.DeviceBudget{Bytes: 100}},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if got := f.be.(*sandboxBackend).evictedIDs(); strings.Join(got, ",") != "g1/1/1" {
					t.Fatalf("evicted %v", got)
				}
				if !f.r.HasDelta(ref) {
					t.Fatal("the park did not happen")
				}
			}},
		{name: "a backend that dumped nothing: the ref comes back with the error", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkNoDir = true
			return cb
		}, grant: g, errText: "but its manifest", wantRef: true,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if ref != f.r.deltaDir(f.fence) {
					t.Fatalf("ref = %q, want the delta dir even on error", ref)
				}
			}},
		{name: "a park stops waiting for the exit when the context ends", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.noExit = true
			return cb
		}, grant: g,
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if !f.r.HasDelta(ref) {
					t.Fatal("the park did not complete")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); !released || !parked {
					t.Fatal("the fiber must stay marked as parked while its exit is pending")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), tc.grant, tc.mod)
			if tc.before != nil {
				tc.before(t, f)
			}
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			ref, err := f.r.Park(ctx, f.h.ID, tc.sync)
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Park = %q, %v, want %v", ref, err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Park = %q, %v, want an error mentioning %q", ref, err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("Park: %v", err)
			}
			if err != nil && !tc.wantRef && ref != "" {
				t.Fatalf("a refused park returned ref %q", ref)
			}
			if tc.check != nil {
				tc.check(t, f, ref)
			}
		})
	}
}

// TestResume checks that a parked delta comes back under a new fence on the
// endpoint it was parked with, after the parent is merged in.
func TestResume(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	handoffG := g
	handoffG.Policy.EndpointMode, handoffG.CallerThumbprint = core.EndpointHandoff, "x5t"
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	// parkFirst parks the fixture's fiber and returns the ref.
	parkFirst := func(t *testing.T, f *parkFixture) string {
		t.Helper()
		ref, err := f.r.Park(context.Background(), f.h.ID, false)
		if err != nil {
			t.Fatalf("Park: %v", err)
		}
		return ref
	}
	// manifestOnly writes a delta directory by hand.
	manifestOnly := func(t *testing.T, f *parkFixture, m manifest, delta *fakeDelta) string {
		t.Helper()
		dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "by-hand")
		write(t, dir, map[string]string{"pages-1.img": "pages"})
		if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
			t.Fatal(err)
		}
		if delta != nil {
			if err := writeJSON(filepath.Join(dir, fakeDeltaFile), delta); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	cases := []struct {
		name  string
		be    func() backend.Backend
		grant core.Grant
		// resumeGrant, when set, is the grant the delta is resumed under
		// instead of grant.
		resumeGrant *core.Grant
		mod         func(*Config)
		ref         func(t *testing.T, f *parkFixture) string
		wantErr     error
		errText     string
		check       func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle)
	}{
		{name: "a unix delta resumes on its parked socket path, under the grant's run directory", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: g, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				sock := filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")
				if h.ID != "g1/2/1" || h.Endpoint != "unix://"+sock {
					t.Fatalf("handle = %+v", h)
				}
				if b, err := os.ReadFile(sock + ".fence"); err != nil || string(b) != "g1/2/1\n" {
					t.Fatalf("fence file = %q %v", b, err)
				}
				cb := f.be.(*codecBackend)
				ff := cb.fiber("g1/2/1")
				if ff == nil || ff.resume == nil || ff.resume.Dir != ref || ff.resume.Endpoint != sock || ff.resume.WarmID != "g1" ||
					ff.resume.WorkDir != filepath.Join(f.r.cfg.RunDir, "g1") || ff.resume.CgroupFD < 0 || ff.resume.Handoff != nil {
					t.Fatalf("resume spec = %+v", ff)
				}
				parent := shaOf("zygote pages of g1")
				if merged, _ := os.ReadFile(filepath.Join(ref, "merged")); string(merged) != parent || len(cb.merged) != 1 {
					t.Fatalf("merged = %q, %v", merged, cb.merged)
				}
				leaf := f.r.root.Child("g1").Child("f-2-1")
				if !leaf.Exists() || cgUint(t, leaf, "memory.max") != 64*mib {
					t.Fatal("the resumed fiber has no leaf of its own")
				}
				// Its end removes the fence file with the rest.
				if err := f.r.Release(context.Background(), h.ID, false); err != nil {
					t.Fatal(err)
				}
				if exists(sock+".fence") || leaf.Exists() {
					t.Fatal("the fence file or the leaf remain")
				}
			}},
		{name: "below the checkpoint tier", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g,
			ref:     func(*testing.T, *parkFixture) string { return "/nonexistent" },
			errText: "resume needs FIBER_CHECKPOINT"},
		{name: "a ref without a manifest", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref:     func(t *testing.T, _ *parkFixture) string { return t.TempDir() },
			wantErr: os.ErrNotExist},
		{name: "a delta parked by another backend", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "runc", Endpoint: "unix:///x.sock"}, nil)
			},
			wantErr: ErrParity, errText: "parked by backend runc, this home runs fake"},
		{name: "a delta whose parent this home lacks", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "unix:///x.sock", Delta: true},
					&fakeDelta{Parent: strings.Repeat("ab", 32), Bytes: 3})
			},
			wantErr: ErrParentMissing, errText: "resume of a delta"},
		{name: "a delta whose info cannot be read", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.infoErr = errors.New("fake: bad delta header")
			return cb
		}, grant: g, ref: parkFirst, errText: "bad delta header"},
		{name: "a merge that fails", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.mergeErr = errors.New("fake: page mismatch")
			return cb
		}, grant: g, ref: parkFirst, errText: "merge delta"},
		{name: "a delta parked on another endpoint family", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "tcp://10.0.0.2:30000"}, nil)
			},
			errText: "parked on a tcp endpoint, this home serves unix",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a delta with an endpoint that does not parse", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "bogus"}, nil)
			},
			errText: "scheme must be unix or tcp",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a restore the backend refuses leaves nothing behind", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.resumeErr = errors.New("fake: criu restore failed")
			return cb
		}, grant: g, ref: parkFirst, errText: "criu restore failed",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
			}},
		{name: "a tcp delta keeps its port across park and resume", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: g,
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				if h.Endpoint != "tcp://127.0.0.1:40000" {
					t.Fatalf("resumed endpoint = %s", h.Endpoint)
				}
				f.r.mu.Lock()
				holder := f.r.ports[40000]
				f.r.mu.Unlock()
				if holder != "g1/2/1" {
					t.Fatalf("port 40000 held by %q, want the new fence", holder)
				}
				fenceFn := filepath.Join(f.r.cfg.RunDir, "g1", "2-1.fence")
				if b, err := os.ReadFile(fenceFn); err != nil || string(b) != "g1/2/1\n" {
					t.Fatalf("fence file = %q %v", b, err)
				}
				if ff := f.be.(*sandboxBackend).fiber("g1/2/1"); ff.resume.Endpoint != "tcp://127.0.0.1:40000" {
					t.Fatalf("the backend was told to serve on %s", ff.resume.Endpoint)
				}
				// Another delta parked on the same port, while the resumed
				// fiber holds it, cannot come back here.
				dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "other")
				write(t, dir, map[string]string{"pages-1.img": "pages"})
				if err := writeJSON(filepath.Join(dir, "manifest.json"), manifest{Fence: "g1/1/9", Backend: "fake", Endpoint: "tcp://127.0.0.1:40000"}); err != nil {
					t.Fatal(err)
				}
				_, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: dir, Fence: core.Fence{GrantUID: "g1", Epoch: 3, Seq: 1}})
				if err == nil || !strings.Contains(err.Error(), "held by g1/2/1") {
					t.Fatalf("resume on a held port = %v", err)
				}
				if f.r.root.Child("g1").Child("f-3-1").Exists() {
					t.Fatal("the refused resume left its leaf")
				}
				// Discarding the parked fiber's delta gives its port back.
				if err := f.r.Release(context.Background(), "g1/2/1", false); err != nil {
					t.Fatal(err)
				}
				if _, err := f.r.Park(context.Background(), "g1/2/1", false); err == nil {
					t.Fatal("parking a released fiber must fail")
				}
			}},
		{name: "a handoff delta gets a fresh channel and no identity message", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: handoffG,
			mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey }, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				if m := readManifest(t, ref); !m.Handoff {
					t.Fatalf("manifest = %+v, want a handoff park", m)
				}
				sb := f.be.(*sandboxBackend)
				ff := sb.fiber("g1/2/1")
				if ff.resume.Endpoint != handoffEndpoint || ff.resume.Handoff == nil || ff.handoff < 0 || ff.identity != nil {
					t.Fatalf("resume = %+v, identity %q", ff.resume, ff.identity)
				}
				if h.Endpoint != "tcp://10.0.0.1:443" {
					t.Fatalf("handle endpoint = %s", h.Endpoint)
				}
				if _, pin, ok := f.r.HandoffRoute(h.ID); !ok || pin == "" {
					t.Fatal("the resumed fiber is not routed")
				}
				if sb.pairs.Load() != 2 {
					t.Fatalf("%d channels made, want one per incarnation", sb.pairs.Load())
				}
			}},
		{name: "a handoff delta on a home that cannot hand off", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Handoff: true}, nil)
			},
			errText: "handoff",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "an id mapper that stops delegating refuses the grant's cgroup", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				*codecMixin
				*selfCheckpointMixin
				*idMapperMixin
			}{newFakeBackend(core.TierCheckpoint), &codecMixin{}, &selfCheckpointMixin{}, &idMapperMixin{uid: 65534}}
		}, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				ref := parkFirst(t, f)
				f.be.(interface{ mapper() *idMapperMixin }).mapper().err = errors.New("fake: range revoked")
				return ref
			},
			errText: "range revoked"},
		{name: "a grant cgroup that refuses another leaf", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant:       g,
			resumeGrant: &core.Grant{UID: "tiny", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib},
			ref: func(t *testing.T, f *parkFixture) string {
				if err := f.r.PrepareTemplate(context.Background(), core.Grant{UID: "tiny", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib}); err != nil {
					t.Fatal(err)
				}
				refuseLeaves(t, f.r.root.Child("tiny"))
				return manifestOnly(t, f, manifest{Fence: "tiny/1/1", Backend: "fake", Endpoint: "unix:///x.sock"}, nil)
			},
			errText: "f-2-1",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("tiny").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a handoff restore the backend refuses closes its channel with the rest", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			grant: handoffG, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			ref: func(t *testing.T, f *parkFixture) string {
				ref := parkFirst(t, f)
				f.be.(*sandboxBackend).resumeErr = errors.New("fake: restore failed")
				return ref
			},
			errText: "restore failed",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
			}},
		{name: "a handoff delta whose channel the backend cannot make", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			return sb
		}, grant: g, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			ref: func(t *testing.T, f *parkFixture) string {
				f.be.(*sandboxBackend).err = errors.New("fake: netns gone")
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Handoff: true}, nil)
			},
			errText: "netns gone",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), tc.grant, tc.mod)
			ref := tc.ref(t, f)
			under := tc.grant
			if tc.resumeGrant != nil {
				under = *tc.resumeGrant
			}
			h, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: under, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("resume = %v, want %v", err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("resume = %v, want an error mentioning %q", err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("resume: %v", err)
			}
			if tc.check != nil {
				tc.check(t, f, ref, h)
			}
		})
	}
}

// TestReleaseDiscard checks that discarding a parked fiber removes its delta
// and frees the port it kept.
func TestReleaseDiscard(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	cases := []struct {
		name    string
		discard bool
		// deltaKept is whether the delta directory survives the release.
		deltaKept bool
		portsHeld int
	}{
		{name: "release without discard keeps the delta and its port", deltaKept: true, portsHeld: 1},
		{name: "release with discard removes the delta and frees the port", discard: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, newSandboxBackend(core.TierSnapshot), g, func(c *Config) { c.Endpoints = tcpPolicy })
			ctx := context.Background()
			ref, err := f.r.Park(ctx, f.h.ID, false)
			if err != nil {
				t.Fatal(err)
			}
			f.r.mu.Lock()
			holder := f.r.ports[40000]
			f.r.mu.Unlock()
			if holder != f.h.ID {
				t.Fatalf("after the park port 40000 is held by %q, want the parked fiber", holder)
			}
			if err := f.r.Release(ctx, f.h.ID, tc.discard); err != nil {
				t.Fatal(err)
			}
			f.r.mu.Lock()
			held := len(f.r.ports)
			f.r.mu.Unlock()
			if exists(ref) != tc.deltaKept || held != tc.portsHeld {
				t.Fatalf("delta exists %v, %d ports held; want %v and %d", exists(ref), held, tc.deltaKept, tc.portsHeld)
			}
		})
	}
}

// TestReleaseOrphan restarts the agent under a live fiber and releases it
// as an orphan. Its leaf goes, and so do the files it served on. A resumed
// fiber keeps the socket name of its park, which only the fence file beside
// it ties to the current fence. Other fibers' files stay.
func TestReleaseOrphan(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	// resumed parks the fixture's fiber and resumes it under next.
	resumed := func(t *testing.T, f *parkFixture) core.Fence {
		t.Helper()
		ref, err := f.r.Park(context.Background(), f.h.ID, false)
		if err != nil {
			t.Fatalf("Park: %v", err)
		}
		if _, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second}); err != nil {
			t.Fatalf("resume: %v", err)
		}
		return next
	}
	cases := []struct {
		name string
		be   func() backend.Backend
		mod  func(*Config)
		// fiber readies the orphan and returns its fence.
		fiber func(t *testing.T, f *parkFixture) core.Fence
		gone  []string // under the grant's run directory
	}{
		{name: "a cloned fiber: its socket by its fence", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.endpointFile = true
			return b
		}, fiber: func(_ *testing.T, f *parkFixture) core.Fence { return f.fence }, gone: []string{"1-1.sock"}},
		{name: "a resumed fiber: the socket it kept from its park and the fence file beside it", be: func() backend.Backend {
			b := newCodecBackend(core.TierCheckpoint)
			b.serve = true
			return b
		}, fiber: resumed, gone: []string{"1-1.sock", "1-1.sock.fence"}},
		{name: "a fiber resumed on tcp: its fence file by its fence", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, fiber: resumed, gone: []string{"2-1.fence"}},
		{name: "a fiber resumed behind a relay: the socket it kept and the fence file beside it", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, fiber: resumed, gone: []string{"1-1.sock", "1-1.sock.fence"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), g, tc.mod)
			orphan := tc.fiber(t, f)
			run := filepath.Join(f.r.cfg.RunDir, "g1")
			for _, n := range tc.gone {
				if !exists(filepath.Join(run, n)) {
					t.Fatalf("%s is not there to begin with", n)
				}
			}
			// Another fiber's socket and fence file, and a fence file that
			// is a link to one naming the orphan, are not the orphan's.
			write(t, run, map[string]string{"9-9.sock": "", "9-9.sock.fence": "g1/9/9\n"})
			named := filepath.Join(t.TempDir(), "named")
			write(t, filepath.Dir(named), map[string]string{"named": orphan.String() + "\n"})
			if err := os.Symlink(named, filepath.Join(run, "8-8.sock.fence")); err != nil {
				t.Fatal(err)
			}
			write(t, run, map[string]string{"8-8.sock": ""})
			kept := []string{"9-9.sock", "9-9.sock.fence", "8-8.sock", "8-8.sock.fence"}

			// A restarted agent over the same directories knows nothing of
			// the fiber, whose leaf still holds a task.
			cfg := f.r.cfg
			cfg.Backend = newFakeBackend(core.TierWarm)
			r, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			leaf := r.root.Child("g1").Child(leafName(orphan))
			startSleeper(t, leaf)
			list, err := r.List(context.Background())
			if err != nil || len(list) != 1 || list[0].ID != orphan.String() {
				t.Fatalf("List = %+v %v, want the orphan alone", list, err)
			}
			if err := r.Release(context.Background(), orphan.String(), false); err != nil {
				t.Fatal(err)
			}
			if leaf.Exists() {
				t.Fatal("the orphan's leaf remains")
			}
			for _, n := range tc.gone {
				if exists(filepath.Join(run, n)) {
					t.Errorf("the orphan's %s remains", n)
				}
			}
			for _, n := range kept {
				if !exists(filepath.Join(run, n)) {
					t.Errorf("%s, not the orphan's, was removed", n)
				}
			}
		})
	}
}

// TestResumeFenceFile checks where a resumed fiber's new fence is
// published and how. A fiber that serves a unix socket, behind a relay
// or not, finds it beside that socket, the one path it knows. One that
// binds tcp itself finds it under the run directory by its new fence.
// The grant's fibers write that directory too, so the agent, which runs
// as root, never writes through a name there. A link a fiber planted is
// replaced, not followed, and a directory denies the fiber its file and
// nothing else. A restore that fails leaves no fence file behind.
func TestResumeFenceFile(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	unixServing := func() backend.Backend {
		b := newCodecBackend(core.TierCheckpoint)
		b.serve = true
		return b
	}
	symlink := func(t *testing.T, fenceFn, victim string) {
		t.Helper()
		if err := os.Symlink(victim, fenceFn); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		be   func() backend.Backend
		mod  func(*Config)
		// file is the fence file's name under the grant's run directory.
		file string
		// plant puts something at that name before the resume.
		plant     func(t *testing.T, fenceFn, victim string)
		resumeErr error
		// wantFile is whether a regular file naming the new fence is
		// there after the resume.
		wantFile bool
	}{
		{name: "unix: beside the socket", be: unixServing, file: "1-1.sock.fence", wantFile: true},
		{name: "relayed tcp: beside the socket the relay dials", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, file: "1-1.sock.fence", wantFile: true},
		{name: "tcp bound by the backend: by the new fence", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, file: "2-1.fence", wantFile: true},
		{name: "unix: a planted link is replaced, not followed", be: unixServing, file: "1-1.sock.fence", plant: symlink, wantFile: true},
		{name: "relayed tcp: a planted link is replaced, not followed", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, file: "1-1.sock.fence", plant: symlink, wantFile: true},
		{name: "tcp bound by the backend: a planted link is replaced, not followed", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, file: "2-1.fence", plant: symlink, wantFile: true},
		{name: "a planted directory denies the file and nothing else", be: unixServing, file: "1-1.sock.fence",
			plant: func(t *testing.T, fenceFn, _ string) {
				t.Helper()
				if err := os.Mkdir(fenceFn, 0o755); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a failed restore leaves no fence file", be: unixServing, file: "1-1.sock.fence", resumeErr: errors.New("fake: criu restore failed")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), g, tc.mod)
			f.fake().resumeErr = tc.resumeErr
			ref, err := f.r.Park(context.Background(), f.h.ID, false)
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			fenceFn := filepath.Join(f.r.cfg.RunDir, "g1", tc.file)
			victim := filepath.Join(t.TempDir(), "victim")
			write(t, filepath.Dir(victim), map[string]string{"victim": "untouched\n"})
			if tc.plant != nil {
				tc.plant(t, fenceFn, victim)
			}
			h, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			if (err != nil) != (tc.resumeErr != nil) {
				t.Fatalf("resume = %+v, %v, want error %v", h, err, tc.resumeErr)
			}
			if b, _ := os.ReadFile(victim); string(b) != "untouched\n" {
				t.Fatalf("the agent wrote through the planted link: victim reads %q", b)
			}
			st, lerr := os.Lstat(fenceFn)
			switch {
			case tc.wantFile:
				if lerr != nil || !st.Mode().IsRegular() {
					t.Fatalf("fence file %s: %v %v, want a regular file", tc.file, st, lerr)
				}
				if b, err := os.ReadFile(fenceFn); err != nil || string(b) != next.String()+"\n" {
					t.Fatalf("fence file = %q %v, want the new fence", b, err)
				}
			case tc.resumeErr != nil:
				if lerr == nil {
					t.Fatalf("the failed resume left %s behind", tc.file)
				}
				if exists(filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")) {
					t.Fatal("the failed resume left the socket name behind")
				}
			default:
				if lerr != nil || !st.IsDir() {
					t.Fatalf("the planted directory %s was replaced: %v %v", tc.file, st, lerr)
				}
			}
			if ents, _ := os.ReadDir(f.r.cfg.RunDir); len(ents) != 1 {
				t.Fatalf("the run directory holds %d entries, want the grant's alone (no temp file left)", len(ents))
			}
			if err == nil {
				if err := f.r.Release(context.Background(), h.ID, true); err != nil {
					t.Fatal(err)
				}
				if exists(fenceFn) && tc.wantFile {
					t.Fatalf("%s remains after the release", tc.file)
				}
			}
		})
	}
}
