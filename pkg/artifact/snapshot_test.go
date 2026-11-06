package artifact_test

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/artifact"
)

// hlPlatform is a Hyperlight home's platform: the helper's facts in the
// kernel and libc fields.
var hlPlatform = artifact.Platform{Arch: "amd64", Kernel: "hyperlight-hyperlight_host/0.18.0", Libc: "example-helper/0.1.0+kvm+GenuineIntel"}

// snapshotTree writes a Hyperlight snapshot as a guest's helper might lay
// one out: a tree with an OCI layout nested in it.
func snapshotTree(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snapshot")
	for name, body := range map[string]string{
		"metadata.json":              "{}",
		"snapshot/index.json":        "{\"schemaVersion\":2}",
		"snapshot/blobs/sha256/aaaa": "guest pages",
		"snapshot/blobs/sha256/bbbb": "guest config",
		"snapshot/oci-layout":        "{}",
		"kernel":                     "kernel bytes",
	} {
		writeFile(t, filepath.Join(dir, name), body)
	}
	return dir
}

// hyperlightArtifact builds a Hyperlight snapshot artifact from tree and
// returns its directory, digest and the home's master.
func hyperlightArtifact(t *testing.T, tree string) (dir, digest string, k *artifact.SealKey) {
	t.Helper()
	k, pub := fleet(t)
	dir = filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(context.Background(), artifact.BuildOptions{HyperlightSnapshot: tree, Out: dir, SealTo: pub, Platform: hlPlatform})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return dir, digest, k
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(root, p)
		got[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestHyperlightArtifact checks that a Hyperlight snapshot travels as an
// artifact's sealed images, under its own media type, with the helper's
// facts as its platform and no zygote, through a registry and back, and
// opens for one warm as a read-only copy of the tree it was built from.
func TestHyperlightArtifact(t *testing.T) {
	ctx := context.Background()
	tree := snapshotTree(t)
	dir, digest, k := hyperlightArtifact(t, tree)

	cfg, err := artifact.ReadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ImagesFormat != artifact.ImagesFormatHyperlight || cfg.Images == nil || cfg.HasZygote() || cfg.ZygoteSHA256 != "" {
		t.Fatalf("config = %+v, want sealed Hyperlight images and no zygote", cfg)
	}
	if cfg.Kernel != hlPlatform.Kernel || cfg.Libc != hlPlatform.Libc {
		t.Fatalf("platform %s/%s, want the helper's facts %s/%s", cfg.Kernel, cfg.Libc, hlPlatform.Kernel, hlPlatform.Libc)
	}
	if _, err := os.Stat(artifact.ZygotePath(dir)); err == nil {
		t.Fatal("the artifact holds a zygote it was not given")
	}
	if _, err := os.Stat(filepath.Join(dir, "images.tar.plain")); err == nil {
		t.Fatal("the plaintext snapshot tar was left")
	}

	reg := newRegistry(t)
	ref := strings.TrimPrefix(reg, "http://") + "/hl/app"
	if _, err := artifact.Push(ctx, dir, "http://"+ref+":v1"); err != nil {
		t.Fatalf("Push: %v", err)
	}
	pulled := filepath.Join(t.TempDir(), "pulled")
	pcfg, err := artifact.Pull(ctx, "http://"+ref+"@"+digest, pulled)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if pcfg.Digest != digest || pcfg.ImagesFormat != artifact.ImagesFormatHyperlight {
		t.Fatalf("pulled %+v", pcfg)
	}
	manifest, _ := os.ReadFile(filepath.Join(pulled, "manifest.json"))
	if !strings.Contains(string(manifest), artifact.MediaTypeHyperlight) || strings.Contains(string(manifest), artifact.MediaTypeImages) ||
		strings.Contains(string(manifest), artifact.MediaTypeBinary) {
		t.Fatalf("manifest layers: %s", manifest)
	}
	if _, err := artifact.Reverify(ctx, pulled, digest); err != nil {
		t.Fatalf("Reverify: %v", err)
	}

	view := filepath.Join(t.TempDir(), "view")
	if err := artifact.OpenSnapshot(pulled, pcfg, k, view); err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	t.Cleanup(func() { _ = artifact.RemoveSnapshot(view) })
	if got, want := readTree(t, view), readTree(t, tree); len(got) != len(want) {
		t.Fatalf("opened %v, want %v", got, want)
	} else {
		for name, body := range want {
			if got[name] != body {
				t.Errorf("%s = %q, want %q", name, got[name], body)
			}
		}
	}
	for path, want := range map[string]os.FileMode{view: 0o500, filepath.Join(view, "snapshot/blobs"): 0o500, filepath.Join(view, "snapshot/blobs/sha256/aaaa"): 0o400} {
		if st, err := os.Lstat(path); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", path, st.Mode(), err, want)
		}
	}
	if _, err := os.Stat(view + ".tar.open"); err == nil {
		t.Error("the opened tar was left beside the snapshot")
	}
	if err := artifact.UnpackImages(pulled, pcfg, k); err == nil || !strings.Contains(err.Error(), "OpenSnapshot") {
		t.Errorf("UnpackImages of a Hyperlight snapshot = %v, want a refusal naming OpenSnapshot", err)
	}
	if err := artifact.RemoveSnapshot(view); err != nil {
		t.Fatalf("RemoveSnapshot: %v", err)
	}
	if _, err := os.Lstat(view); err == nil {
		t.Fatal("RemoveSnapshot left the snapshot")
	}
	if err := artifact.RemoveSnapshot(view); err != nil {
		t.Fatalf("RemoveSnapshot of nothing = %v", err)
	}
}

func TestOpenSnapshotRefuses(t *testing.T) {
	tree := snapshotTree(t)
	dir, _, k := hyperlightArtifact(t, tree)
	cfg, _ := artifact.ReadConfig(dir)
	other, _ := fleet(t)
	cases := []struct {
		name    string
		cfg     func() artifact.Config
		k       *artifact.SealKey
		wantErr string
	}{
		{name: "no seal key", cfg: func() artifact.Config { return cfg }, wantErr: "-delta-seal-key"},
		{name: "another fleet's master", cfg: func() artifact.Config { return cfg }, k: other, wantErr: "this home derives"},
		{name: "CRIU images", k: k, wantErr: "no Hyperlight snapshot", cfg: func() artifact.Config {
			c := cfg
			c.ImagesFormat = ""
			return c
		}},
		{name: "a config whose hash is not the snapshot's", k: k, wantErr: "sealed", cfg: func() artifact.Config {
			c := cfg
			s := *c.Images
			s.SHA256 = strings.Repeat("0", 64)
			c.Images = &s
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := filepath.Join(t.TempDir(), "view")
			err := artifact.OpenSnapshot(dir, tc.cfg(), tc.k, view)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("OpenSnapshot = %v, want an error containing %q", err, tc.wantErr)
			}
			if _, err := os.Lstat(view); err == nil {
				t.Fatal("a refused open left the snapshot")
			}
			if _, err := os.Lstat(view + ".tar.open"); err == nil {
				t.Fatal("a refused open left the plaintext tar")
			}
		})
	}
}

// TestHyperlightArtifactRefuses checks what a Hyperlight snapshot
// artifact may not be: built without the fleet key or the helper's facts,
// from something other than a tree of directories and regular files, or
// carrying an executable its config does not vouch for.
func TestHyperlightArtifactRefuses(t *testing.T) {
	_, pub := fleet(t)
	t.Run("build", func(t *testing.T) {
		cases := []struct {
			name    string
			o       func(t *testing.T) artifact.BuildOptions
			wantErr string
		}{
			{name: "without the fleet key", wantErr: "-seal-to", o: func(t *testing.T) artifact.BuildOptions {
				return artifact.BuildOptions{HyperlightSnapshot: snapshotTree(t), Out: t.TempDir(), Platform: hlPlatform}
			}},
			{name: "without the helper's facts", wantErr: "hyperlight.PlatformOf", o: func(t *testing.T) artifact.BuildOptions {
				return artifact.BuildOptions{HyperlightSnapshot: snapshotTree(t), Out: t.TempDir(), SealTo: pub, Platform: artifact.Platform{Arch: "amd64"}}
			}},
			{name: "from a file", wantErr: "not a directory", o: func(t *testing.T) artifact.BuildOptions {
				f := filepath.Join(t.TempDir(), "f")
				writeFile(t, f, "x")
				return artifact.BuildOptions{HyperlightSnapshot: f, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a tree with a symlink", wantErr: "neither a directory nor a regular file", o: func(t *testing.T) artifact.BuildOptions {
				tree := snapshotTree(t)
				if err := os.Symlink("/etc/passwd", filepath.Join(tree, "snapshot", "evil")); err != nil {
					t.Fatal(err)
				}
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a tree with a fifo", wantErr: "neither a directory nor a regular file", o: func(t *testing.T) artifact.BuildOptions {
				tree := snapshotTree(t)
				if err := syscall.Mkfifo(filepath.Join(tree, "fifo"), 0o600); err != nil {
					t.Fatal(err)
				}
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a symlink to a tree", wantErr: "not a directory", o: func(t *testing.T) artifact.BuildOptions {
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(snapshotTree(t), link); err != nil {
					t.Fatal(err)
				}
				return artifact.BuildOptions{HyperlightSnapshot: link, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "an output inside the snapshot", wantErr: "overlap", o: func(t *testing.T) artifact.BuildOptions {
				tree := snapshotTree(t)
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: filepath.Join(tree, "out"), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "the snapshot as the output", wantErr: "overlap", o: func(t *testing.T) artifact.BuildOptions {
				tree := snapshotTree(t)
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: tree, SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a snapshot inside the output", wantErr: "overlap", o: func(t *testing.T) artifact.BuildOptions {
				out := t.TempDir()
				tree := filepath.Join(out, "snap")
				if err := os.CopyFS(tree, os.DirFS(snapshotTree(t))); err != nil {
					t.Fatal(err)
				}
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: out, SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a tree with no file", wantErr: "holds no file", o: func(t *testing.T) artifact.BuildOptions {
				tree := t.TempDir()
				if err := os.MkdirAll(filepath.Join(tree, "snapshot", "blobs"), 0o755); err != nil {
					t.Fatal(err)
				}
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
			{name: "a tree with a name that is not plain", wantErr: "not a plain file name", o: func(t *testing.T) artifact.BuildOptions {
				tree := snapshotTree(t)
				writeFile(t, filepath.Join(tree, "has space"), "x")
				return artifact.BuildOptions{HyperlightSnapshot: tree, Out: t.TempDir(), SealTo: pub, Platform: hlPlatform}
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				o := tc.o(t)
				if _, err := artifact.Build(context.Background(), o); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Build = %v, want an error containing %q", err, tc.wantErr)
				}
				if _, err := os.Stat(filepath.Join(o.Out, "images.tar.plain")); err == nil {
					t.Fatal("a refused build left the plaintext tar")
				}
			})
		}
	})
	t.Run("an executable the config does not vouch for", func(t *testing.T) {
		dir, _, _ := hyperlightArtifact(t, snapshotTree(t))
		writeFile(t, artifact.ZygotePath(dir), "#!/bin/sh\n")
		if _, err := artifact.Pack(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "without a hash") {
			t.Fatalf("Pack = %v, want a refusal of the unvouched zygote", err)
		}
	})
	t.Run("a cached artifact rewritten on disk", func(t *testing.T) {
		cases := []struct {
			name    string
			edit    func(t *testing.T, dir string)
			wantErr string
		}{
			{name: "an executable the config does not vouch for", wantErr: "without a hash",
				edit: func(t *testing.T, dir string) { writeFile(t, artifact.ZygotePath(dir), "#!/bin/sh\n") }},
			{name: "an images format this fiberd does not know", wantErr: "unknown images format",
				edit: func(t *testing.T, dir string) {
					editConfig(t, dir, func(c *artifact.Config) { c.ImagesFormat = "firecracker" })
				}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dir, digest, _ := hyperlightArtifact(t, snapshotTree(t))
				tc.edit(t, dir)
				if _, err := artifact.Reverify(context.Background(), dir, digest); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Reverify = %v, want an error containing %q", err, tc.wantErr)
				}
			})
		}
	})
	t.Run("an images format this fiberd does not know", func(t *testing.T) {
		dir, _, _ := hyperlightArtifact(t, snapshotTree(t))
		editConfig(t, dir, func(c *artifact.Config) { c.ImagesFormat = "firecracker" })
		if _, err := artifact.Pack(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "unknown images format") {
			t.Fatalf("Pack = %v, want a refusal of the format", err)
		}
	})
	t.Run("a zygote given to the build", func(t *testing.T) {
		zyg := filepath.Join(t.TempDir(), "z")
		writeFile(t, zyg, "#!/bin/sh\n")
		out := t.TempDir()
		if _, err := artifact.Build(context.Background(), artifact.BuildOptions{HyperlightSnapshot: snapshotTree(t), Zygote: zyg, Out: out, SealTo: pub, Platform: hlPlatform}); err == nil || !strings.Contains(err.Error(), "carries no zygote") {
			t.Fatalf("Build = %v, want a zygote refused", err)
		}
	})
	t.Run("a config that names a zygote", func(t *testing.T) {
		dir, _, _ := hyperlightArtifact(t, snapshotTree(t))
		editConfig(t, dir, func(c *artifact.Config) { c.ZygoteSHA256 = strings.Repeat("a", 64) })
		if _, err := artifact.Pack(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "carries no zygote") {
			t.Fatalf("Pack = %v, want the named zygote refused", err)
		}
	})
}

// TestSnapshotTarRefuses checks the unpack side of a snapshot tar: a tar
// sealed to the fleet that holds anything but plain names in a tree of
// directories and regular files opens to nothing.
func TestSnapshotTarRefuses(t *testing.T) {
	cases := []struct {
		name    string
		wantErr string
		entries []*tar.Header
	}{
		{name: "an escape", wantErr: "not a plain file name", entries: []*tar.Header{{Name: "../evil", Typeflag: tar.TypeReg}}},
		{name: "an absolute name", wantErr: "not a plain file name", entries: []*tar.Header{{Name: "/etc/evil", Typeflag: tar.TypeReg}}},
		{name: "a symlink", wantErr: "neither a directory nor a regular file", entries: []*tar.Header{{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}},
		{name: "a hard link", wantErr: "neither a directory nor a regular file", entries: []*tar.Header{{Name: "evil", Typeflag: tar.TypeLink, Linkname: "metadata.json"}}},
		{name: "a file before its directory", wantErr: "no such file or directory", entries: []*tar.Header{{Name: "a/b", Typeflag: tar.TypeReg}}},
		{name: "a name twice", wantErr: "file exists", entries: []*tar.Header{{Name: "a", Typeflag: tar.TypeReg}, {Name: "a", Typeflag: tar.TypeReg}}},
		{name: "a name that is not clean", wantErr: "not a plain file name", entries: []*tar.Header{{Name: "a/", Typeflag: tar.TypeDir}, {Name: "a//b", Typeflag: tar.TypeReg}}},
		{name: "too deep", wantErr: "not a plain file name", entries: func() []*tar.Header {
			var hs []*tar.Header
			name := ""
			for i := 0; i < 17; i++ {
				name += "d/"
				hs = append(hs, &tar.Header{Name: name, Typeflag: tar.TypeDir})
			}
			return hs
		}()},
	}
	k, pub := fleet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := hyperlightArtifact(t, snapshotTree(t))
			plain := filepath.Join(t.TempDir(), "plain.tar")
			f, err := os.Create(plain)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(f)
			for _, h := range tc.entries {
				h.Mode = 0o600
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
			}
			_ = tw.Close()
			_ = f.Close()
			s, err := artifact.SealImages(plain, filepath.Join(dir, "images.tar"), pub)
			if err != nil {
				t.Fatal(err)
			}
			editConfig(t, dir, func(c *artifact.Config) { c.Images = &s })
			cfg, _ := artifact.ReadConfig(dir)
			view := filepath.Join(t.TempDir(), "view")
			if err := artifact.OpenSnapshot(dir, cfg, k, view); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("OpenSnapshot = %v, want an error containing %q", err, tc.wantErr)
			}
			if _, err := os.Lstat(view); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused tar left %s: %v", view, err)
			}
			if _, err := os.Lstat("/etc/evil"); err == nil {
				t.Fatal("the tar wrote outside its destination")
			}
		})
	}
}

// TestTarSnapshotIsStable checks that one tree always tars to the same
// bytes, so a rebuild of an unchanged snapshot names the same images.
func TestTarSnapshotIsStable(t *testing.T) {
	tree := snapshotTree(t)
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if err := artifact.TarSnapshot(tree, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(tree, "kernel"), time.Unix(12345, 0), time.Unix(12345, 0)); err != nil {
		t.Fatal(err)
	}
	if err := artifact.TarSnapshot(tree, b); err != nil {
		t.Fatal(err)
	}
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	if string(x) != string(y) {
		t.Fatal("the same tree tarred to different bytes")
	}
}

// TestSnapshotTarRefusesASparseEntry checks that a tar whose entry
// expands to far more than the tar holds opens to nothing. archive/tar
// expands a PAX GNU sparse entry by itself, so testdata/sparse.tar, 10
// KiB that say 1 GiB (made with Python's tarfile), would otherwise write
// the whole gigabyte of zeros at every warm.
func TestSnapshotTarRefusesASparseEntry(t *testing.T) {
	k, pub := fleet(t)
	dir, _, _ := hyperlightArtifact(t, snapshotTree(t))
	s, err := artifact.SealImages(filepath.Join("testdata", "sparse.tar"), filepath.Join(dir, "images.tar"), pub)
	if err != nil {
		t.Fatal(err)
	}
	editConfig(t, dir, func(c *artifact.Config) { c.Images = &s })
	cfg, _ := artifact.ReadConfig(dir)
	view := filepath.Join(t.TempDir(), "view")
	if err := artifact.OpenSnapshot(dir, cfg, k, view); err == nil || !strings.Contains(err.Error(), "sparse") {
		t.Fatalf("OpenSnapshot = %v, want the sparse entry refused", err)
	}
	if _, err := os.Lstat(view); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused tar left %s: %v", view, err)
	}
}

// TestOpenSnapshotLeavesWhatIsThere checks that a destination already
// there is refused and kept, never removed as a failed open's leftovers.
func TestOpenSnapshotLeavesWhatIsThere(t *testing.T) {
	dir, _, k := hyperlightArtifact(t, snapshotTree(t))
	cfg, _ := artifact.ReadConfig(dir)
	dst := filepath.Join(t.TempDir(), "theirs")
	writeFile(t, filepath.Join(dst, "keep"), "x")
	if err := artifact.OpenSnapshot(dir, cfg, k, dst); err == nil || !strings.Contains(err.Error(), "already there") {
		t.Fatalf("OpenSnapshot = %v, want the destination refused", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "keep")); err != nil {
		t.Fatalf("a refused open took what was there: %v", err)
	}
	// Nor through its plaintext tar's name.
	fresh := filepath.Join(t.TempDir(), "fresh")
	target := filepath.Join(t.TempDir(), "target")
	writeFile(t, target, "precious")
	if err := os.Symlink(target, fresh+".tar.open"); err != nil {
		t.Fatal(err)
	}
	if err := artifact.OpenSnapshot(dir, cfg, k, fresh); err == nil || !strings.Contains(err.Error(), "already there") {
		t.Fatalf("OpenSnapshot = %v, want the tar's name refused", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "precious" {
		t.Fatalf("the open wrote through the tar's name: %q", b)
	}
	if _, err := os.Lstat(fresh); err == nil {
		t.Fatal("a refused open left its destination")
	}
}
