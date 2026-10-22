//go:build linux

package host

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host/wsfs"
)

// uploadString puts body at path in the fiber's workspace through the
// runtime's file store.
func uploadString(t *testing.T, r *Runtime, fiberID, path, body string) {
	t.Helper()
	if _, err := r.Upload(context.Background(), fiberID, path, int64(len(body)), 0o644, nil, strings.NewReader(body)); err != nil {
		t.Fatalf("upload %s: %v", path, err)
	}
}

// downloadString reads path from the fiber's workspace through the
// runtime's file store.
func downloadString(t *testing.T, r *Runtime, fiberID, path string) string {
	t.Helper()
	f, err := r.Download(context.Background(), fiberID, path, 0)
	if err != nil {
		t.Fatalf("download %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// tarNames lists the entries of the tar at path, a regular file's name
// followed by "=" and its content.
func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var names []string
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			names = append(names, h.Name+"="+string(b))
			continue
		}
		names = append(names, h.Name)
	}
}

// TestWorkspaceLifecycle checks that a fiber of a grant with a disk
// budget is born with an empty workspace under WorkspaceDir, that the
// backend is handed its root to mount, that the file calls reach it,
// and that it goes with the fiber. A grant without a budget gets none,
// and a birth the backend refuses leaves nothing behind.
func TestWorkspaceLifecycle(t *testing.T) {
	cases := []struct {
		name     string
		disk     uint64
		cloneErr error
		want     bool // a workspace is made and handed to the backend
	}{
		{name: "a grant with a disk budget gets a workspace", disk: 1 << 20, want: true},
		{name: "a grant without one gets none", disk: 0},
		{name: "a birth the backend refuses leaves no workspace", disk: 1 << 20, cloneErr: errors.New("no fork")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newWorkspaceBackend(core.TierCheckpoint)
			be.cloneErr = tc.cloneErr
			r := newTestRuntime(t, be, nil)
			if !slices.Contains(r.hide, r.cfg.WorkspaceDir) {
				t.Fatalf("hidden %v, want the workspace dir %s among them", r.hide, r.cfg.WorkspaceDir)
			}
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib, DiskBudgetBytes: tc.disk}
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
			dir := r.workspaceDir(fence)
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, CallerCert: callerDER})
			if tc.cloneErr != nil {
				if err == nil || !strings.Contains(err.Error(), tc.cloneErr.Error()) {
					t.Fatalf("Clone = %v, want %v", err, tc.cloneErr)
				}
				if exists(dir) {
					t.Fatalf("%s remains after the refused birth", dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			root := filepath.Join(dir, "root")
			be.mu.Lock()
			spec := be.fibers[h.ID].spec
			be.mu.Unlock()
			if !tc.want {
				if spec.Workspace != "" || exists(dir) {
					t.Fatalf("backend got workspace %q and %s exists, want neither for a grant without a disk budget", spec.Workspace, dir)
				}
				if _, err := r.Upload(ctx, h.ID, "a.txt", 1, 0o644, nil, strings.NewReader("x")); !errors.Is(err, core.ErrNoWorkspace) {
					t.Fatalf("Upload = %v, want ErrNoWorkspace", err)
				}
			} else {
				if spec.Workspace != root {
					t.Fatalf("backend got workspace %q, want %s", spec.Workspace, root)
				}
				// root is the fiber's tree, 0755 as wsfs makes it. What keeps
				// other users out is its 0700 parent, the fiber's own
				// workspace directory.
				st, err := os.Stat(root)
				if err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
					t.Fatalf("root %s: %v %v, want a 0755 directory", root, st, err)
				}
				if pst, err := os.Stat(filepath.Dir(root)); err != nil || pst.Mode().Perm() != 0o700 {
					t.Fatalf("workspace %s: %v %v, want a 0700 directory", filepath.Dir(root), pst, err)
				}
				if ents, _ := os.ReadDir(root); len(ents) != 0 {
					t.Fatalf("a fresh workspace holds %d entries, want none", len(ents))
				}
				uploadString(t, r, h.ID, "in/data.txt", "hello")
				if b, err := os.ReadFile(filepath.Join(root, "in", "data.txt")); err != nil || string(b) != "hello" {
					t.Fatalf("the upload landed as %q, %v", b, err)
				}
				if got := downloadString(t, r, h.ID, "in/data.txt"); got != "hello" {
					t.Fatalf("download = %q", got)
				}
				infos, err := r.ListFiles(ctx, h.ID, "in")
				if err != nil || len(infos) != 1 || infos[0].Path != "in/data.txt" || infos[0].Size != 5 {
					t.Fatalf("ListFiles = %+v, %v", infos, err)
				}
				if _, err := r.Download(ctx, h.ID, "../etc/passwd", 0); !errors.Is(err, wsfs.ErrPath) {
					t.Fatalf("Download of a climbing path = %v, want ErrPath", err)
				}
			}
			if _, err := r.Upload(ctx, "g1/1/99", "a.txt", 1, 0o644, nil, strings.NewReader("x")); !errors.Is(err, core.ErrFiberUnknown) {
				t.Fatalf("Upload to an unknown fiber = %v, want ErrFiberUnknown", err)
			}
			if err := r.Release(ctx, h.ID, false); err != nil {
				t.Fatalf("Release: %v", err)
			}
			if exists(dir) {
				t.Fatalf("%s remains after the fiber ended", dir)
			}
			if _, err := r.Upload(ctx, h.ID, "a.txt", 1, 0o644, nil, strings.NewReader("x")); !errors.Is(err, core.ErrFiberUnknown) {
				t.Fatalf("Upload after the end = %v, want ErrFiberUnknown", err)
			}
		})
	}
}

// TestWorkspaceOwner checks that a backend that maps the grant's root
// into a user namespace (runc) gets workspaces owned by that root, the
// tree and every file fiberd writes into it, so the fiber, uid 0
// inside, can write what it was given. A mapper that refuses the grant
// at the birth leaves no workspace. The mapped root here is the test's
// own uid, the one owner a chown without privilege may name. The
// foreign uid is tests/integration/runc TestWorkspaceRoundTrip.
func TestWorkspaceOwner(t *testing.T) {
	cases := []struct {
		name    string
		mapper  bool
		refuse  bool // the mapper refuses once the template is prepared
		wantErr string
	}{
		{name: "no mapper keeps fiberd's ids"},
		{name: "the mapped root owns the tree and the uploads", mapper: true},
		{name: "a mapper that refuses at the birth leaves no workspace", mapper: true, refuse: true, wantErr: "workspace owner of grant g1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid := os.Geteuid(), os.Getegid()
			if tc.mapper && uid != 0 && uid != gid {
				t.Skip("the mapped root's gid is its uid, which this user cannot chown to")
			}
			var be backend.Backend = newWorkspaceBackend(core.TierCheckpoint)
			m := &idMapperMixin{uid: uint32(uid)}
			if tc.mapper {
				be = &struct {
					workspaceCodecBackend
					*idMapperMixin
				}{newWorkspaceBackend(core.TierCheckpoint), m}
			}
			r := newTestRuntime(t, be, nil)
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib, DiskBudgetBytes: 1 << 20}
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			if tc.refuse {
				m.err = errors.New("fake: range revoked")
			}
			fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
			dir := r.workspaceDir(fence)
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, CallerCert: callerDER})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Clone = %v, want %q", err, tc.wantErr)
				}
				if exists(dir) {
					t.Fatalf("%s remains after the refused birth", dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			defer func() { _ = r.Release(ctx, h.ID, false) }()
			uploadString(t, r, h.ID, "in/data.txt", "hello")
			wantGID := gid
			if tc.mapper {
				wantGID = uid
			}
			for _, rel := range []string{"root", "root/in", "root/in/data.txt"} {
				st, err := os.Lstat(filepath.Join(dir, rel))
				if err != nil {
					t.Fatal(err)
				}
				sys, _ := st.Sys().(*syscall.Stat_t)
				if sys == nil || int(sys.Uid) != uid || int(sys.Gid) != wantGID {
					t.Fatalf("%s is owned by %v, want %d:%d", rel, sys, uid, wantGID)
				}
			}
		})
	}
}

// TestWorkspacePark checks that a park captures the workspace into
// workspace.tar beside the images, through the backend's Capture with
// the fiber's leaf, that the workspace goes with the parked fiber, and
// that a resume unpacks the archive into a fresh workspace the backend
// is handed, with the files where the dump saw them.
func TestWorkspacePark(t *testing.T) {
	cases := []struct {
		name string
		sync bool
	}{
		{name: "async"},
		{name: "sync"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newWorkspaceBackend(core.TierCheckpoint)
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib, DiskBudgetBytes: 1 << 20}
			f := newParkFixture(t, be, g, nil)
			ctx := context.Background()
			uploadString(t, f.r, f.h.ID, "in/data.txt", "hello")
			uploadString(t, f.r, f.h.ID, "note", "n")
			dir := f.r.workspaceDir(f.fence)
			ref, err := f.r.Park(ctx, f.h.ID, tc.sync)
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			parks := f.fake().parked()
			if len(parks) != 1 || parks[0].Capture == nil || parks[0].CgroupFD < 0 {
				t.Fatalf("backend parks = %+v, want one with a capture and the leaf", parks)
			}
			want := []string{"in/", "in/data.txt=hello", "note=n"}
			if got := tarNames(t, filepath.Join(ref, workspaceTar)); !slices.Equal(got, want) {
				t.Fatalf("%s holds %v, want %v", workspaceTar, got, want)
			}
			if st, err := os.Stat(filepath.Join(ref, workspaceTar)); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v, want fiberd's alone", workspaceTar, st, err)
			}
			waitFor(t, "the parked fiber's workspace to go", func() bool { return !exists(dir) })
			if tc.sync && len(f.fake().killedIDs()) != 1 {
				t.Fatal("a sync park ends the fiber once the delta is durable")
			}
			next := core.Fence{GrantUID: g.UID, Epoch: 2, Seq: 1}
			h2, err := f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			root2 := filepath.Join(f.r.workspaceDir(next), "root")
			rs := f.fake().fiber(h2.ID).resume
			if rs == nil || rs.Workspace != root2 {
				t.Fatalf("backend resumed with %+v, want workspace %s", rs, root2)
			}
			if b, err := os.ReadFile(filepath.Join(root2, "in", "data.txt")); err != nil || string(b) != "hello" {
				t.Fatalf("the unpacked file is %q, %v", b, err)
			}
			if got := downloadString(t, f.r, h2.ID, "in/data.txt"); got != "hello" {
				t.Fatalf("download after the resume = %q", got)
			}
			if err := f.r.Release(ctx, h2.ID, true); err != nil {
				t.Fatalf("Release: %v", err)
			}
			if exists(f.r.workspaceDir(next)) {
				t.Fatal("the resumed fiber's workspace remains after its release")
			}
		})
	}
}

// TestWorkspaceParkRefused checks that a park the workspace refuses, or
// one the delta quota refuses for the workspace's size, leaves the
// fiber running with its workspace, and no archive behind.
func TestWorkspaceParkRefused(t *testing.T) {
	cases := []struct {
		name string
		// grant's budgets. The delta quota is 4 x fibers.max x W.
		fiberMax int
		w, disk  uint64
		before   func(t *testing.T, f *parkFixture, root string)
		parkErr  error
		wantErr  error
		errText  string
		// wantDumps is how many times the backend was asked to park.
		wantDumps int
	}{
		{name: "a hard link from the host fails the capture", fiberMax: 2, w: 64 * mib, disk: 1 << 20,
			before: func(t *testing.T, f *parkFixture, root string) {
				host := filepath.Join(t.TempDir(), "host.txt")
				if err := os.WriteFile(host, []byte("host bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(host, filepath.Join(root, "link")); err != nil {
					t.Skipf("hard link across the temp directory: %v", err)
				}
			}, wantErr: wsfs.ErrForeignLink, wantDumps: 1},
		{name: "a workspace past the delta quota is refused before the dump", fiberMax: 1, w: mib, disk: 8 * mib,
			before: func(t *testing.T, f *parkFixture, _ string) {
				uploadString(t, f.r, f.h.ID, "big", strings.Repeat("x", 5*mib))
			}, wantErr: core.ErrDeltaQuota, errText: "adds about"},
		{name: "a dump that fails keeps the workspace", fiberMax: 2, w: 64 * mib, disk: 1 << 20, parkErr: errors.New("dump failed"), errText: "dump failed", wantDumps: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newWorkspaceBackend(core.TierCheckpoint)
			be.parkErr = tc.parkErr
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: tc.fiberMax, WBudgetBytes: tc.w, DiskBudgetBytes: tc.disk}
			f := newParkFixture(t, be, g, nil)
			ctx := context.Background()
			uploadString(t, f.r, f.h.ID, "in/data.txt", "hello")
			dir := f.r.workspaceDir(f.fence)
			if tc.before != nil {
				tc.before(t, f, filepath.Join(dir, "root"))
			}
			ref, err := f.r.Park(ctx, f.h.ID, false)
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("Park = %q, %v, want %v with %q", ref, err, tc.wantErr, tc.errText)
			}
			if ref != "" {
				t.Fatalf("a refused park returned %q", ref)
			}
			if n := len(f.fake().parked()); n != tc.wantDumps {
				t.Fatalf("the backend was asked to park %d times, want %d", n, tc.wantDumps)
			}
			if released, parked := f.fiberFlags(t, f.h.ID); released || parked {
				t.Fatal("the fiber is still marked parked after the refusal")
			}
			if !exists(filepath.Join(dir, "root", "in", "data.txt")) {
				t.Fatal("the workspace did not survive the refused park")
			}
			delta := f.r.deltaDir(f.fence)
			for _, p := range []string{filepath.Join(delta, workspaceTar), filepath.Join(delta+".failed", workspaceTar)} {
				if exists(p) {
					t.Fatalf("%s remains after the refused park", p)
				}
			}
			if got := downloadString(t, f.r, f.h.ID, "in/data.txt"); got != "hello" {
				t.Fatalf("download after the refused park = %q", got)
			}
			noExit(t, f.r)
		})
	}
}

// TestWorkspaceResumeRefused checks that a delta and a grant that do not
// agree on a workspace are refused before the backend restores, as is a
// hostile archive, and that a restore the backend refuses leaves no
// workspace behind.
func TestWorkspaceResumeRefused(t *testing.T) {
	cases := []struct {
		name         string
		parkDisk     uint64 // the parking grant's disk budget
		resumeDisk   uint64 // the resuming grant's
		tamper       func(t *testing.T, ref string)
		resumeErr    error
		errText      string
		wantRestores int
	}{
		{name: "a delta with a workspace under a grant without a disk budget", parkDisk: 1 << 20, resumeDisk: 0, errText: "carries a workspace, but grant g1 has no disk budget"},
		{name: "a delta without a workspace under a grant with a disk budget", parkDisk: 0, resumeDisk: 1 << 20, errText: "has no workspace.tar, but grant g1 has a disk budget"},
		{name: "a hostile archive is refused", parkDisk: 1 << 20, resumeDisk: 1 << 20, errText: "unpack workspace.tar",
			tamper: func(t *testing.T, ref string) {
				var buf bytes.Buffer
				tw := tar.NewWriter(&buf)
				if err := tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}); err != nil {
					t.Fatal(err)
				}
				_, _ = tw.Write([]byte("x"))
				_ = tw.Close()
				if err := os.WriteFile(filepath.Join(ref, workspaceTar), buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a restore the backend refuses leaves no workspace", parkDisk: 1 << 20, resumeDisk: 1 << 20, resumeErr: errors.New("no restore"), errText: "no restore", wantRestores: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newWorkspaceBackend(core.TierCheckpoint)
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib, DiskBudgetBytes: tc.parkDisk}
			f := newParkFixture(t, be, g, nil)
			ctx := context.Background()
			if tc.parkDisk > 0 {
				uploadString(t, f.r, f.h.ID, "a.txt", "a")
			}
			ref, err := f.r.Park(ctx, f.h.ID, false)
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			if tc.tamper != nil {
				tc.tamper(t, ref)
			}
			be.resumeErr = tc.resumeErr
			next := core.Fence{GrantUID: g.UID, Epoch: 2, Seq: 1}
			g.DiskBudgetBytes = tc.resumeDisk
			_, err = f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			if err == nil || !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("resume = %v, want %q", err, tc.errText)
			}
			// Resume calls, since a refused restore records no fiber.
			be.mu.Lock()
			restores := be.resumeCalls
			be.mu.Unlock()
			if restores != tc.wantRestores {
				t.Fatalf("the backend restored %d times, want %d", restores, tc.wantRestores)
			}
			if exists(f.r.workspaceDir(next)) {
				t.Fatal("the refused resume left a workspace behind")
			}
			if f.r.root.Child(g.UID).Child(leafName(next)).Exists() {
				t.Fatal("the refused resume left its leaf behind")
			}
			f.r.mu.Lock()
			n := len(f.r.fibers)
			f.r.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d fibers after the refused resume, want none", n)
			}
		})
	}
}

// TestWorkspaceSweep checks that what an earlier fiberd left under the
// workspace directory is gone once the runtime opens, and that the
// directory is fiberd's alone.
func TestWorkspaceSweep(t *testing.T) {
	cases := []struct {
		name string
		left []string // paths under WorkspaceDir before New
	}{
		{name: "nothing left"},
		{name: "a dead fiber's tree", left: []string{"g1/1-1/root/in/data.txt", "g1/1-1/.stage/7.1"}},
		{name: "a stray file", left: []string{"junk"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newWorkspaceBackend(core.TierCheckpoint)
			cfg := testConfig(t, be)
			for _, p := range tc.left {
				full := filepath.Join(cfg.WorkspaceDir, p)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("old"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			r, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(r.Close)
			ents, err := os.ReadDir(cfg.WorkspaceDir)
			if err != nil || len(ents) != 0 {
				t.Fatalf("workspace dir holds %d entries after the sweep (%v), want none", len(ents), err)
			}
			if st, err := os.Stat(cfg.WorkspaceDir); err != nil || st.Mode().Perm() != 0o700 {
				t.Fatalf("workspace dir mode %v, %v, want 0700", st, err)
			}
		})
	}
}
