//go:build linux

package host

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/Azure/fiberd/pkg/artifact"
	"github.com/Azure/fiberd/pkg/backend"
	"github.com/Azure/fiberd/pkg/core"
)

// hlHost is a Hyperlight home's platform: its helper's facts where the
// kernel and libc go.
var hlHost = artifact.Platform{Arch: "amd64", Kernel: "hyperlight-hyperlight_host/0.18.0", Libc: "example-helper/0.1.0+kvm+GenuineIntel"}

// snapshotArtifact builds a Hyperlight snapshot artifact recording p,
// sealed to templateMaster's fleet key, pushes it to reg and returns its
// digest.
func snapshotArtifact(t *testing.T, reg string, p artifact.Platform) string {
	t.Helper()
	tree := t.TempDir()
	for name, body := range map[string]string{"metadata.json": "{}", "snapshot/index.json": "{}", "snapshot/blobs/sha256/aa": "guest pages"} {
		path := filepath.Join(tree, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w, err := artifact.DeriveWrapKey(templateMaster)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, err := artifact.Build(context.Background(), artifact.BuildOptions{HyperlightSnapshot: tree, Out: out, Args: []string{"--x"}, SealTo: w.Public(), Platform: p}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	digest, err := artifact.Push(context.Background(), out, reg+"/tmpl/x:hl-"+strings.NewReplacer("/", "-", "+", "-").Replace(p.Libc))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	return digest
}

// newTemplateRegistry is an in-memory OCI registry for the test's
// templates, as its URL.
func newTemplateRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	return srv.URL
}

func gone(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// TestSnapshotTemplate checks how a home takes a template whose artifact
// carries a Hyperlight snapshot: only on a backend that restores that
// format, only on the platform its helper's facts name, and as a
// read-only copy of the warm's own, which goes when the warm does.
func TestSnapshotTemplate(t *testing.T) {
	ctx := context.Background()
	reg := newTemplateRegistry(t)
	hl := snapshotArtifact(t, reg, hlHost)
	elsewhere := snapshotArtifact(t, reg, artifact.Platform{Arch: "amd64", Kernel: hlHost.Kernel, Libc: "example-helper/0.2.0+kvm+GenuineIntel"})
	runtime := func(t *testing.T, be backend.Backend, key *artifact.SealKey, platform ...*artifact.Platform) *Runtime {
		return newTestRuntime(t, be, func(c *Config) {
			c.Templates, c.Registry = nil, reg+"/tmpl/x"
			c.Platform = hlHost
			if len(platform) > 0 && platform[0] != nil {
				c.Platform = *platform[0]
			}
			c.DeltaKeys.Seal = key
		})
	}

	t.Run("refused", func(t *testing.T) {
		cases := []struct {
			name     string
			be       backend.Backend
			key      *artifact.SealKey
			digest   string
			platform *artifact.Platform // nil for the helper's
			wantIs   error
			wantErr  string
		}{
			{name: "by a backend that restores no snapshot", be: newCodecBackend(core.TierCheckpoint), key: templateMaster, digest: hl,
				wantIs: ErrNoTemplate, wantErr: "does not restore"},
			// Before parity, whose advice could not help: the home's own
			// platform is not the helper's here.
			{name: "by a backend that restores no snapshot, on a platform of its own", be: newCodecBackend(core.TierCheckpoint), key: templateMaster, digest: hl,
				platform: &artifact.Platform{Arch: "amd64", Kernel: "6.1.0-test", Libc: "(gnu libc) 2.36"}, wantIs: ErrNoTemplate, wantErr: "does not restore"},
			{name: "by a backend that can restore none now", be: newSnapshotBackend(""), key: templateMaster, digest: hl,
				wantIs: ErrNoTemplate, wantErr: "does not restore"},
			{name: "by a backend that restores another format", be: newSnapshotBackend("firecracker"), key: templateMaster, digest: hl,
				wantIs: ErrNoTemplate, wantErr: "does not restore"},
			{name: "when another helper made it", be: newSnapshotBackend(artifact.ImagesFormatHyperlight), key: templateMaster, digest: elsewhere,
				wantIs: ErrParity, wantErr: "0.2.0"},
			{name: "without the seal key", be: newSnapshotBackend(artifact.ImagesFormatHyperlight), digest: hl,
				wantIs: ErrNoTemplate, wantErr: "-delta-seal-key"},
			// Before parity, whose advice could not help: the backend runs no
			// template's executable at all.
			{name: "a template without a snapshot, by a backend that restores one", be: newSnapshotBackend(artifact.ImagesFormatHyperlight), key: templateMaster,
				digest: templateArtifact(t, reg, artifact.Platform{Arch: "amd64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, artifact.LinkDynamic),
				wantIs: ErrNoTemplate, wantErr: "carries none"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rt := runtime(t, tc.be, tc.key, tc.platform)
				err := rt.PrepareTemplate(ctx, core.Grant{UID: "g1", TemplateDigest: tc.digest, WBudgetBytes: 64 << 20})
				if !errors.Is(err, tc.wantIs) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PrepareTemplate = %v, want %v saying %q", err, tc.wantIs, tc.wantErr)
				}
				if ents, _ := os.ReadDir(rt.snapshotsDir()); len(ents) != 0 {
					t.Fatalf("a refused template left %d snapshots", len(ents))
				}
			})
		}
	})

	t.Run("each warm gets a read-only copy of its own", func(t *testing.T) {
		be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
		rt := runtime(t, be, templateMaster)
		if err := rt.PrepareTemplate(ctx, core.Grant{UID: "g1", TemplateDigest: hl, WBudgetBytes: 64 << 20}); err != nil {
			t.Fatalf("PrepareTemplate: %v", err)
		}
		if err := rt.PrepareTemplate(ctx, core.Grant{UID: "g2", TemplateDigest: hl, WBudgetBytes: 64 << 20}); err != nil {
			t.Fatalf("PrepareTemplate: %v", err)
		}
		s1, _ := be.warmSpec("g1")
		s2, _ := be.warmSpec("g2")
		view := s1.Template.SnapshotDir
		if view == "" || filepath.Dir(view) != rt.snapshotsDir() || view == s2.Template.SnapshotDir {
			t.Fatalf("snapshots %q and %q, want two of their own under %s", view, s2.Template.SnapshotDir, rt.snapshotsDir())
		}
		if got, err := os.ReadFile(filepath.Join(view, "snapshot/blobs/sha256/aa")); err != nil || string(got) != "guest pages" {
			t.Fatalf("snapshot reads %q %v", got, err)
		}
		for path, want := range map[string]os.FileMode{view: 0o500, filepath.Join(view, "metadata.json"): 0o400, rt.snapshotsDir(): 0o700} {
			if st, err := os.Lstat(path); err != nil || st.Mode().Perm() != want {
				t.Errorf("%s: %v %v, want %v", path, st.Mode(), err, want)
			}
		}
		if tpl := s1.Template; tpl.ImagesDir != "" || tpl.ZygoteSHA256 != "" || strings.Join(tpl.Argv, " ") != " --x" {
			t.Errorf("template = %+v, want the artifact's arguments, no executable and no CRIU images", tpl)
		}
		if n := len(rt.imagesHeld); n != 0 {
			t.Errorf("%d images held for a snapshot", n)
		}
		// A dropped warm takes its copy, and leaves the other's.
		rt.DropTemplate("g1")
		if !gone(view) {
			t.Error("a dropped warm left its snapshot")
		}
		if gone(s2.Template.SnapshotDir) {
			t.Error("dropping one warm took another's snapshot")
		}
		// So does one whose instance ended.
		be.warmGone("g2")
		waitFor(t, "the ended warm's snapshot to go", func() bool { return gone(s2.Template.SnapshotDir) })
	})

	t.Run("a warm that fails leaves no snapshot", func(t *testing.T) {
		be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
		be.warmErr = errors.New("helper did not become ready")
		rt := runtime(t, be, templateMaster)
		if err := rt.PrepareTemplate(ctx, core.Grant{UID: "g1", TemplateDigest: hl, WBudgetBytes: 64 << 20}); err == nil {
			t.Fatal("PrepareTemplate succeeded")
		}
		if ents, _ := os.ReadDir(rt.snapshotsDir()); len(ents) != 0 {
			t.Fatalf("a failed warm left %d snapshots", len(ents))
		}
	})

	t.Run("a start sweeps what an earlier fiberd left", func(t *testing.T) {
		be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
		rt := runtime(t, be, templateMaster)
		if err := rt.PrepareTemplate(ctx, core.Grant{UID: "g1", TemplateDigest: hl, WBudgetBytes: 64 << 20}); err != nil {
			t.Fatalf("PrepareTemplate: %v", err)
		}
		s, _ := be.warmSpec("g1")
		open := s.Template.SnapshotDir + "x.tar.open"
		if err := os.WriteFile(open, []byte("plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
		rt.sweepStores()
		if !gone(s.Template.SnapshotDir) || !gone(open) {
			t.Fatal("the sweep left a snapshot or its plaintext tar")
		}
	})
}

// TestCloseRemovesSnapshots checks that a home that closes with warm
// instances up removes their snapshots itself, since their exits may
// never be read.
func TestCloseRemovesSnapshots(t *testing.T) {
	reg := newTemplateRegistry(t)
	hl := snapshotArtifact(t, reg, hlHost)
	be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
	cfg := testConfig(t, be)
	cfg.Templates, cfg.Registry, cfg.Platform, cfg.DeltaKeys.Seal = nil, reg+"/tmpl/x", hlHost, templateMaster
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.PrepareTemplate(context.Background(), core.Grant{UID: "g1", TemplateDigest: hl, WBudgetBytes: 64 << 20}); err != nil {
		t.Fatalf("PrepareTemplate: %v", err)
	}
	s, _ := be.warmSpec("g1")
	rt.Close()
	if !gone(s.Template.SnapshotDir) {
		t.Fatal("Close left a warm's snapshot")
	}
}

// TestPrepareTemplateIsSingleFlight checks that concurrent prepares of
// one grant, as concurrent clones that warm it on demand after its
// instance ended make, warm it once and open one snapshot, which goes
// with that warm.
func TestPrepareTemplateIsSingleFlight(t *testing.T) {
	reg := newTemplateRegistry(t)
	hl := snapshotArtifact(t, reg, hlHost)
	be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
	gate := make(chan struct{})
	be.warmGate = gate
	rt := newTestRuntime(t, be, func(c *Config) {
		c.Templates, c.Registry, c.Platform, c.DeltaKeys.Seal = nil, reg+"/tmpl/x", hlHost, templateMaster
	})
	g := core.Grant{UID: "g1", TemplateDigest: hl, WBudgetBytes: 64 << 20}
	const callers = 4
	errs := make(chan error, callers)
	for range callers {
		go func() { errs <- rt.PrepareTemplate(context.Background(), g) }()
	}
	waitFor(t, "a prepare to reach the backend", func() bool {
		be.mu.Lock()
		defer be.mu.Unlock()
		return be.warmCalls > 0
	})
	// The others would reach Warm in this time if they ran beside it.
	time.Sleep(100 * time.Millisecond)
	close(gate)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("PrepareTemplate: %v", err)
		}
	}
	be.mu.Lock()
	calls := be.warmCalls
	be.mu.Unlock()
	if calls != 1 {
		t.Fatalf("%d warms for one grant", calls)
	}
	ents, _ := os.ReadDir(rt.snapshotsDir())
	if len(ents) != 1 {
		t.Fatalf("%d snapshots opened for one grant", len(ents))
	}
	rt.DropTemplate("g1")
	if ents, _ := os.ReadDir(rt.snapshotsDir()); len(ents) != 0 {
		t.Fatalf("%d snapshots left after the warm was dropped", len(ents))
	}
}

// TestADroppedWarmsEndLeavesItsSuccessor checks that the end of a warm
// instance the host dropped, which a backend that names warms by grant
// reports after a re-warm of the grant has the same WarmID, does not end
// the re-warm or remove its snapshot.
func TestADroppedWarmsEndLeavesItsSuccessor(t *testing.T) {
	ctx := context.Background()
	reg := newTemplateRegistry(t)
	hl := snapshotArtifact(t, reg, hlHost)
	be := newSnapshotBackend(artifact.ImagesFormatHyperlight)
	rt := newTestRuntime(t, be, func(c *Config) {
		c.Templates, c.Registry, c.Platform, c.DeltaKeys.Seal = nil, reg+"/tmpl/x", hlHost, templateMaster
	})
	prepare := func(uid string) backend.WarmSpec {
		t.Helper()
		if err := rt.PrepareTemplate(ctx, core.Grant{UID: uid, TemplateDigest: hl, WBudgetBytes: 64 << 20}); err != nil {
			t.Fatalf("PrepareTemplate %s: %v", uid, err)
		}
		s, _ := be.warmSpec(uid)
		return s
	}
	prepare("g1")
	rt.mu.Lock()
	dropped := rt.warms["g1"].instance
	rt.mu.Unlock()
	rt.DropTemplate("g1")
	successor := prepare("g1").Template.SnapshotDir
	other := prepare("g2").Template.SnapshotDir

	be.exits <- backend.Exit{WarmID: "g1", Instance: dropped, Status: "helper exited"}
	// The pump reads exits in order, so once g2's end is handled the
	// dropped instance's was too.
	be.warmGone("g2")
	waitFor(t, "g2's snapshot to go", func() bool { return gone(other) })
	rt.mu.Lock()
	_, warm := rt.warms["g1"]
	rt.mu.Unlock()
	if !warm || gone(successor) {
		t.Fatalf("the dropped instance's end took its successor (warm %v, snapshot gone %v)", warm, gone(successor))
	}
	// The successor's own end still goes.
	be.warmGone("g1")
	waitFor(t, "the successor's snapshot to go", func() bool { return gone(successor) })
}
