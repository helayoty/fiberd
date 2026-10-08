package artifact_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/grant"
)

// A registry in this process: go-containerregistry's in-memory
// implementation of the OCI distribution API.
func newRegistry(t *testing.T) string {
	t.Helper()
	reg, _ := newFaultyRegistry(t, nil)
	return reg
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// imagesArtifact fakes, without CRIU, what a Pull of an artifact with
// images leaves in the template cache. That is the zygote, its config,
// the images archive and the unpacked images.
func imagesArtifact(t *testing.T) (dir, digest string) {
	t.Helper()
	dir = t.TempDir()
	zygote := "#!/bin/sh\necho READY\n"
	writeFile(t, artifact.ZygotePath(dir), zygote)
	sum := sha256.Sum256([]byte(zygote))
	b, err := json.Marshal(artifact.Config{Args: []string{"--x"}, Arch: runtime.GOARCH, ZygoteSHA256: hex.EncodeToString(sum[:]), HasImages: true})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "config.json"), string(b))
	pages := t.TempDir()
	writeFile(t, filepath.Join(pages, "pages-1.img"), "template pages")
	if err := artifact.TarDir(pages, filepath.Join(dir, "images.tar")); err != nil {
		t.Fatal(err)
	}
	if err := artifact.Untar(filepath.Join(dir, "images.tar"), artifact.ImagesDir(dir)); err != nil {
		t.Fatal(err)
	}
	if digest, err = artifact.Pack(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	return dir, digest
}

// TestBuildPushPullRoundTrip builds a zygote into an artifact, pushes it
// to a registry and pulls it back. The steps run in order because each
// builds on the last.
func TestBuildPushPullRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "zygote.sh")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho READY\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A relative output directory, as the Make targets use: the store must
	// resolve layer paths against it, not join it twice.
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	out := "art"
	reg := newRegistry(t)
	ref := reg + "/zygotes/test:v1"
	var (
		digest string
		cfg    artifact.Config
	)

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"build into a relative directory records the zygote and its args", func(t *testing.T) {
			var err error
			digest, err = artifact.Build(ctx, artifact.BuildOptions{Zygote: src, Args: []string{"--heap-mb", "8"}, Out: out, SkipImages: true})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(digest, "sha256:") {
				t.Fatalf("digest = %q", digest)
			}
			if cfg, err = artifact.ReadConfig(out); err != nil {
				t.Fatal(err)
			}
			if cfg.Arch == "" || cfg.ZygoteSHA256 == "" || cfg.HasImages || len(cfg.Args) != 2 {
				t.Fatalf("config = %+v", cfg)
			}
		}},
		{"packing again is deterministic", func(t *testing.T) {
			again, err := artifact.Pack(ctx, out)
			if err != nil || again != digest {
				t.Fatalf("repack digest = %s (%v), want %s", again, err, digest)
			}
		}},
		{"push returns the packed digest", func(t *testing.T) {
			pushed, err := artifact.Push(ctx, out, ref, true)
			if err != nil {
				t.Fatal(err)
			}
			if pushed != digest {
				t.Fatalf("push digest = %s, want the packed digest %s", pushed, digest)
			}
		}},
		{"pull by digest restores an executable zygote and records the digest", func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "pulled")
			got, err := artifact.Pull(ctx, reg+"/zygotes/test@"+digest, dst, true)
			if err != nil {
				t.Fatal(err)
			}
			if got.Digest != digest || got.ZygoteSHA256 != cfg.ZygoteSHA256 {
				t.Fatalf("pulled config = %+v", got)
			}
			a, _ := os.ReadFile(src)
			b, err := os.ReadFile(artifact.ZygotePath(dst))
			if err != nil || string(a) != string(b) {
				t.Fatalf("pulled zygote differs: %v", err)
			}
			if st, err := os.Stat(artifact.ZygotePath(dst)); err != nil || st.Mode()&0o100 == 0 {
				t.Fatalf("pulled zygote not executable: %v", err)
			}
			if d, err := artifact.ReadDigest(dst); err != nil || d != digest {
				t.Fatalf("recorded digest = %s (%v)", d, err)
			}
		}},
		{"pull by tag works too", func(t *testing.T) {
			if _, err := artifact.Pull(ctx, ref, filepath.Join(t.TempDir(), "bytag"), true); err != nil {
				t.Fatalf("pull by tag: %v", err)
			}
		}},
		{"a wrong digest is refused by the transfer", func(t *testing.T) {
			bogus := "sha256:" + strings.Repeat("0", 64)
			if _, err := artifact.Pull(ctx, reg+"/zygotes/test@"+bogus, filepath.Join(t.TempDir(), "bogus"), true); err == nil {
				t.Fatal("pull of a nonexistent digest succeeded")
			}
		}},
		{"a cached artifact is reverified and its images unpacked afresh", func(t *testing.T) {
			cases := []struct {
				name   string
				mutate func(t *testing.T, dir string, digest *string)
				ok     bool
			}{
				{name: "untouched", ok: true},
				{name: "images rewritten are replaced from images.tar", ok: true, mutate: func(t *testing.T, dir string, _ *string) {
					writeFile(t, filepath.Join(artifact.ImagesDir(dir), "pages-1.img"), "evil pages")
				}},
				{name: "zygote rewritten", mutate: func(t *testing.T, dir string, _ *string) {
					writeFile(t, artifact.ZygotePath(dir), "#!/bin/sh\necho EVIL\n")
				}},
				{name: "config rewritten", mutate: func(t *testing.T, dir string, _ *string) {
					b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
					writeFile(t, filepath.Join(dir, "config.json"), strings.Replace(string(b), `"--x"`, `"--y"`, 1))
				}},
				{name: "images.tar rewritten", mutate: func(t *testing.T, dir string, _ *string) {
					writeFile(t, filepath.Join(dir, "images.tar"), "not a tar")
				}},
				{name: "another digest", mutate: func(t *testing.T, _ string, digest *string) {
					*digest = "sha256:" + strings.Repeat("0", 64)
				}},
				{name: "images never unpacked are unpacked", ok: true, mutate: func(t *testing.T, dir string, _ *string) {
					if err := os.RemoveAll(artifact.ImagesDir(dir)); err != nil {
						t.Fatal(err)
					}
				}},
				{name: "config missing", mutate: func(t *testing.T, dir string, _ *string) {
					remove(t, filepath.Join(dir, "config.json"))
				}},
				{name: "zygote missing", mutate: func(t *testing.T, dir string, _ *string) {
					remove(t, artifact.ZygotePath(dir))
				}},
				// The next two pack to the digest asked for. What fails is
				// the content under it.
				{name: "a config naming another zygote", mutate: func(t *testing.T, dir string, digest *string) {
					editConfig(t, dir, func(c *artifact.Config) { c.ZygoteSHA256 = strings.Repeat("0", 64) })
					*digest = repack(t, dir)
				}},
				{name: "images.tar that never was an archive", mutate: func(t *testing.T, dir string, digest *string) {
					writeFile(t, filepath.Join(dir, "images.tar"), strings.Repeat("x", 1024))
					*digest = repack(t, dir)
				}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					dir, digest := imagesArtifact(t)
					if c.mutate != nil {
						c.mutate(t, dir, &digest)
					}
					got, err := artifact.Reverify(ctx, dir, digest)
					for _, side := range []string{".verified", ".old"} {
						if _, serr := os.Stat(artifact.ImagesDir(dir) + side); !errors.Is(serr, os.ErrNotExist) {
							t.Fatalf("images%s left behind: %v", side, serr)
						}
					}
					if !c.ok {
						if err == nil {
							t.Fatal("reverify accepted a changed artifact")
						}
						return
					}
					if err != nil || got.Digest != digest || !got.HasImages {
						t.Fatalf("reverify = %+v, %v", got, err)
					}
					if b, _ := os.ReadFile(filepath.Join(artifact.ImagesDir(dir), "pages-1.img")); string(b) != "template pages" {
						t.Fatalf("images/pages-1.img = %q, want the verified archive's", b)
					}
				})
			}
		}},
		{"a signed directory verifies from the registry manifest alone", func(t *testing.T) {
			k, err := grant.GenerateKey(jose.EdDSA)
			if err != nil {
				t.Fatal(err)
			}
			keys := artifact.Keys{Signer: k}
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "pages-1.img"), "dirty pages")
			writeFile(t, filepath.Join(dir, "manifest.json"), "{}")
			ann := map[string]string{artifact.AnnotationSession: "S"}
			for _, signer := range []*jose.JSONWebKey{k, nil} {
				tag := reg + "/deltas/d:signed"
				if signer == nil {
					tag = reg + "/deltas/d:unsigned"
				}
				if _, err := artifact.PushDir(ctx, dir, tag, artifact.ArtifactTypeDelta, ann, signer, true); err != nil {
					t.Fatal(err)
				}
				loc, found, err := artifact.Resolve(ctx, tag, true)
				if err != nil || !found || len(loc.Files) != 2 {
					t.Fatalf("resolve %s: %+v %v %v", tag, loc, found, err)
				}
				err = keys.Verify(loc)
				if signer != nil && err != nil {
					t.Fatalf("verify signed: %v", err)
				}
				if signer == nil && !errors.Is(err, artifact.ErrUntrusted) {
					t.Fatalf("verify unsigned = %v, want ErrUntrusted", err)
				}
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}

// tarEntries lists an archive's entries as name -> body, failing on any
// entry that is not a regular file.
func tarEntries(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got := map[string]string{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg || !hdr.ModTime.Equal(time.Unix(0, 0)) || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" {
			t.Fatalf("entry %+v is not a reproducible regular file", hdr)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = string(b)
	}
}

// TestTarDir checks that only the regular files directly under the
// directory are archived, flat and reproducibly.
func TestTarDir(t *testing.T) {
	plain := map[string]string{"pages-1.img": "pages", "core-1.img": "core"}
	cases := []struct {
		name  string
		setup func(t *testing.T, src string)
		dst   func(t *testing.T) string
		want  map[string]string
	}{
		{name: "regular files are archived by name", want: plain},
		{name: "subdirectories are left out", want: plain, setup: func(t *testing.T, src string) {
			writeFile(t, filepath.Join(src, "sub", "inner.img"), "inner")
		}},
		{name: "symbolic links are left out", want: plain, setup: func(t *testing.T, src string) {
			if err := os.Symlink(filepath.Join(src, "pages-1.img"), filepath.Join(src, "link.img")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(src, "missing"), filepath.Join(src, "dangling.img")); err != nil {
				t.Fatal(err)
			}
		}},
		// Opening a FIFO blocks until a writer comes, so archiving one
		// would hang.
		{name: "named pipes are left out", want: plain, setup: func(t *testing.T, src string) {
			if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a missing source fails", setup: func(t *testing.T, src string) {
			if err := os.RemoveAll(src); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "an archive that cannot be created fails", dst: func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "missing", "out.tar")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := t.TempDir()
			for name, body := range plain {
				writeFile(t, filepath.Join(src, name), body)
			}
			if c.setup != nil {
				c.setup(t, src)
			}
			dst := filepath.Join(t.TempDir(), "out.tar")
			if c.dst != nil {
				dst = c.dst(t)
			}
			done := make(chan error, 1)
			go func() { done <- artifact.TarDir(src, dst) }()
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("TarDir hangs")
			}
			if c.want == nil {
				if err == nil {
					t.Fatal("TarDir succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("TarDir: %v", err)
			}
			if got := tarEntries(t, dst); !maps.Equal(got, c.want) {
				t.Fatalf("archived %v, want %v", got, c.want)
			}
			// The same files with other times archive to the same bytes.
			later := time.Now().Add(time.Hour)
			for name := range plain {
				if err := os.Chtimes(filepath.Join(src, name), later, later); err != nil {
					t.Fatal(err)
				}
			}
			again := filepath.Join(t.TempDir(), "again.tar")
			if err := artifact.TarDir(src, again); err != nil {
				t.Fatal(err)
			}
			a, _ := os.ReadFile(dst)
			b, _ := os.ReadFile(again)
			if !bytes.Equal(a, b) {
				t.Fatal("archiving again after a touch changed the bytes")
			}
		})
	}
}

// TestUntar checks that an archive unpacks flat into the directory and
// that no entry reaches outside it.
func TestUntar(t *testing.T) {
	type entry struct {
		name, body, link string
		typ              byte
		size             int64 // header size when it differs from the body's
	}
	archive := func(t *testing.T, entries ...entry) string {
		t.Helper()
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			typ := e.typ
			if typ == 0 {
				typ = tar.TypeReg
			}
			size := int64(len(e.body))
			if e.size != 0 {
				size = e.size
			}
			if typ != tar.TypeReg {
				size = 0
			}
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: typ, Linkname: e.link, Size: size, Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(e.body)); err != nil && e.size == 0 {
				t.Fatal(err)
			}
		}
		// A truncated entry leaves the writer short. Keep what it wrote.
		_ = tw.Flush()
		path := filepath.Join(t.TempDir(), "in.tar")
		writeFile(t, path, buf.String())
		return path
	}
	raw := func(body string) func(t *testing.T) string {
		return func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "in.tar")
			writeFile(t, path, body)
			return path
		}
	}
	cases := []struct {
		name string
		src  func(t *testing.T) string
		dst  func(t *testing.T, root string) string
		want map[string]string // the unpacked directory, nil when it must fail
	}{
		{name: "regular entries unpack by name", want: map[string]string{"a.img": "A", "b.img": "B"},
			src: func(t *testing.T) string {
				return archive(t, entry{name: "a.img", body: "A"}, entry{name: "b.img", body: "B"})
			}},
		{name: "entry paths are reduced to their base name", want: map[string]string{"escape": "E", "deep": "D"},
			src: func(t *testing.T) string {
				return archive(t, entry{name: "../../escape", body: "E"}, entry{name: "/abs/dir/deep", body: "D"})
			}},
		{name: "links and directories are skipped", want: map[string]string{"a.img": "A"},
			src: func(t *testing.T) string {
				return archive(t, entry{name: "evil", typ: tar.TypeSymlink, link: "/etc/passwd"},
					entry{name: "sub", typ: tar.TypeDir}, entry{name: "hard", typ: tar.TypeLink, link: "a.img"},
					entry{name: "a.img", body: "A"})
			}},
		{name: "an empty file is an empty archive", want: map[string]string{}, src: raw("")},
		{name: "an entry named after the parent fails without writing it",
			src: func(t *testing.T) string { return archive(t, entry{name: "..", body: "P"}) }},
		{name: "a truncated entry fails",
			src: func(t *testing.T) string { return archive(t, entry{name: "a.img", body: "short", size: 4096}) }},
		{name: "a header that does not parse fails", src: raw(strings.Repeat("x", 1024))},
		{name: "a missing archive fails", src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.tar") }},
		{name: "a destination under a regular file fails",
			src: func(t *testing.T) string { return archive(t, entry{name: "a.img", body: "A"}) },
			dst: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "file"), "")
				return filepath.Join(root, "file", "out")
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			dst := filepath.Join(root, "a", "b", "out")
			if c.dst != nil {
				dst = c.dst(t, root)
			}
			err := artifact.Untar(c.src(t), dst)
			if c.want == nil {
				if err == nil {
					t.Fatal("Untar succeeded")
				}
			} else if err != nil {
				t.Fatalf("Untar: %v", err)
			}
			// Nothing lands beside the destination, whatever the entries
			// say. A failed unpack may leave part of an entry inside it.
			got := map[string]string{}
			_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(dst, path)
				if c.dst != nil && rel == ".." {
					return nil // the regular file in the way
				}
				if c.want == nil && !strings.HasPrefix(rel, "..") {
					return nil
				}
				b, _ := os.ReadFile(path)
				got[rel] = string(b)
				return nil
			})
			want := c.want
			if want == nil {
				want = map[string]string{}
			}
			if !maps.Equal(got, want) {
				t.Fatalf("unpacked %v, want %v", got, want)
			}
		})
	}
}

// zygoteDir writes an artifact directory with a zygote and a config
// that matches it.
func zygoteDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	zygote := "#!/bin/sh\necho READY >&3\n"
	writeFile(t, artifact.ZygotePath(dir), zygote)
	sum := sha256.Sum256([]byte(zygote))
	writeConfig(t, dir, artifact.Config{Args: []string{"-v"}, Arch: runtime.GOARCH, ZygoteSHA256: hex.EncodeToString(sum[:])})
	return dir
}

func writeConfig(t *testing.T, dir string, c artifact.Config) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "config.json"), string(b))
}

func editConfig(t *testing.T, dir string, f func(*artifact.Config)) {
	t.Helper()
	c, err := artifact.ReadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	f(&c)
	writeConfig(t, dir, c)
}

func repack(t *testing.T, dir string) string {
	t.Helper()
	d, err := artifact.Pack(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestPush(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(t *testing.T, dir string)
		mw    middleware
		ref   string // under the registry
		want  string // a substring of the error, "" for success
		check func(t *testing.T, reg, digest string)
	}{
		{name: "a push without a tag is pulled by its digest", ref: "z",
			check: func(t *testing.T, reg, digest string) {
				if c, err := artifact.Pull(context.Background(), reg+"/z@"+digest, t.TempDir(), true); err != nil || c.Digest != digest {
					t.Fatalf("Pull = %+v, %v", c, err)
				}
			}},
		{name: "a push needs config.json", ref: "z:t", want: "config.json",
			edit: func(t *testing.T, dir string) { remove(t, filepath.Join(dir, "config.json")) }},
		{name: "a config that is not JSON", ref: "z:t", want: "artifact: config.json",
			edit: func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "config.json"), "{") }},
		{name: "a push needs the zygote", ref: "z:t", want: "missing zygote",
			edit: func(t *testing.T, dir string) { remove(t, artifact.ZygotePath(dir)) }},
		{name: "a reference that does not parse", ref: "UPPER:t", want: "UPPER"},
		{name: "a registry that refuses the push", ref: "z:t", want: "artifact: push",
			mw: answer(http.MethodPost, "blob", "", http.StatusForbidden)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, arm := newFaultyRegistry(t, c.mw)
			arm()
			dir := zygoteDir(t)
			if c.edit != nil {
				c.edit(t, dir)
			}
			d, err := artifact.Push(context.Background(), dir, reg+"/"+c.ref, true)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Push = %s, %v; want an error about %q", d, err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c.check(t, reg, d)
		})
	}
}

func TestPull(t *testing.T) {
	ctx := context.Background()
	pushZygote := func(t *testing.T, reg, dir string) {
		t.Helper()
		if _, err := artifact.Push(ctx, dir, reg+"/z:t", true); err != nil {
			t.Fatal(err)
		}
	}
	// pushAs pushes only the named files of a zygote directory, as a
	// directory artifact of type typ.
	pushAs := func(typ string, names ...string) func(t *testing.T, reg string) {
		return func(t *testing.T, reg string) {
			src, part := zygoteDir(t), t.TempDir()
			for _, n := range names {
				b, err := os.ReadFile(filepath.Join(src, n))
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(part, n), string(b))
			}
			if _, err := artifact.PushDir(ctx, part, reg+"/z:t", typ, nil, nil, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name    string
		setup   func(t *testing.T, reg string)
		ref     string // under the registry, z:t by default
		dstFile bool   // the destination is under a regular file
		want    string // a substring of the error, "" for success
	}{
		{name: "the images are unpacked beside the zygote", setup: func(t *testing.T, reg string) {
			dir, _ := imagesArtifact(t)
			pushZygote(t, reg, dir)
		}},
		{name: "a pull needs a tag or digest", ref: "z", want: "needs repo@digest or repo:tag"},
		{name: "a reference that does not parse", ref: "UPPER:t", want: "UPPER"},
		{name: "a destination under a regular file", dstFile: true, want: "not a directory"},
		{name: "a directory artifact is not a zygote", want: "not a zygote artifact",
			setup: pushAs(artifact.ArtifactTypeDelta, "zygote", "config.json")},
		{name: "an artifact without a zygote", want: "zygote",
			setup: pushAs(artifact.ArtifactType, "config.json")},
		{name: "an artifact without a config", want: "config.json",
			setup: pushAs(artifact.ArtifactType, "zygote")},
		{name: "a zygote that does not match its config", want: "does not match config",
			setup: func(t *testing.T, reg string) {
				dir := zygoteDir(t)
				editConfig(t, dir, func(c *artifact.Config) { c.ZygoteSHA256 = strings.Repeat("0", 64) })
				pushZygote(t, reg, dir)
			}},
		{name: "a config that promises images it does not carry", want: "images.tar",
			setup: func(t *testing.T, reg string) {
				dir := zygoteDir(t)
				editConfig(t, dir, func(c *artifact.Config) { c.HasImages = true })
				pushZygote(t, reg, dir)
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := newRegistry(t)
			if c.setup != nil {
				c.setup(t, reg)
			} else {
				pushZygote(t, reg, zygoteDir(t))
			}
			root := t.TempDir()
			dst := filepath.Join(root, "pulled")
			if c.dstFile {
				writeFile(t, filepath.Join(root, "file"), "")
				dst = filepath.Join(root, "file", "pulled")
			}
			ref := "z:t"
			if c.ref != "" {
				ref = c.ref
			}
			cfg, err := artifact.Pull(ctx, reg+"/"+ref, dst, true)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Pull = %+v, %v; want an error about %q", cfg, err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.HasImages || cfg.Digest == "" {
				t.Fatalf("Pull = %+v", cfg)
			}
			if b, err := os.ReadFile(filepath.Join(artifact.ImagesDir(dst), "pages-1.img")); err != nil || string(b) != "template pages" {
				t.Fatalf("images/pages-1.img = %q, %v", b, err)
			}
		})
	}
}
