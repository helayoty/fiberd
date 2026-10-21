//go:build linux && integration

package systest

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// execFile writes a script and makes it executable.
func execFile(t *testing.T, path, body string) {
	t.Helper()
	mustWrite(t, path, []byte(body))
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// tarEntries lists an archive's regular entries as name -> body.
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
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = string(b)
	}
}

// fleet is a master seal key and the public wrap key authors seal images
// to.
func fleet(t *testing.T) (*artifact.SealKey, *artifact.WrapPublicKey) {
	t.Helper()
	jwk, err := artifact.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := artifact.SealKeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	w, err := artifact.DeriveWrapKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, w.Public()
}

// openedImages opens the sealed images.tar of the artifact in out with
// the master and lists its entries. The build must have left nothing of
// the images in the clear.
func openedImages(t *testing.T, out string, k *artifact.SealKey) map[string]string {
	t.Helper()
	for _, left := range []string{artifact.ImagesDir(out), filepath.Join(out, "images.tar.plain")} {
		if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the build left %s in the clear: %v", left, err)
		}
	}
	cfg, err := artifact.ReadConfig(out)
	if err != nil || cfg.Images == nil {
		t.Fatalf("config = %+v, %v; want sealed images", cfg, err)
	}
	opened := filepath.Join(t.TempDir(), "images.tar")
	if err := artifact.OpenImages(filepath.Join(out, "images.tar"), opened, k, *cfg.Images); err != nil {
		t.Fatal(err)
	}
	return tarEntries(t, opened)
}

// Zygotes speak on fd 3, as a home's do. The second moves its channel
// off fd 3 before it is ready.
const (
	readyZygote   = "#!/bin/sh\necho READY >&3\nexec sleep 600\n"
	closingZygote = "#!/bin/sh\nexec 4>&3 3>&-\necho READY >&4\nexec sleep 600\n"
)

// buildCriu stands in for criu at a build. It records the dump's
// arguments and writes one page image into the -D directory, or fails
// with fail when told to.
type buildCriu struct {
	fail string
	args []string
}

func (c *buildCriu) Output(_ context.Context, args []string) ([]byte, error) {
	c.args = args
	if c.fail != "" {
		return []byte(c.fail), errors.New("exit status 1")
	}
	dir := ""
	for i, a := range args {
		if a == "-D" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	return nil, os.WriteFile(filepath.Join(dir, "pages-1.img"), []byte("pages\n"), 0o600)
}

func (c *buildCriu) Start([]string, []*os.File, int) (criu.Process, error) {
	return nil, errors.New("a build never restores")
}

// TestArtifactBuildCheckpoint runs Build's checkpoint of a shell zygote
// against a criu stand-in. The zygote is a real process, so the
// handshake over fd 3, its exit, the external socket named to criu and
// the scratch directory are all checked as a build sees them.
func TestArtifactBuildCheckpoint(t *testing.T) {
	cases := []struct {
		name     string
		zygote   string
		fail     string // the criu stand-in fails with this
		timeout  time.Duration
		canceled bool
		want     string // a substring of the error, "" for success
		external bool   // the control socket is named external to criu
		// taken names a path under the output directory that something
		// else holds before the build.
		taken string
	}{
		{name: "a ready zygote is dumped left running, its control socket external", zygote: readyZygote, external: true},
		{name: "a zygote with nothing on fd 3 has no socket to name", zygote: closingZygote},
		{name: "a zygote that says something else", zygote: "#!/bin/sh\necho HELLO >&3\nexec sleep 600\n", want: `said "HELLO"`},
		{name: "a zygote that exits first", zygote: "#!/bin/sh\nexit 3\n", want: "zygote"},
		// A child keeps the channel open, so only the exit tells.
		{name: "a zygote that exits first, its child holding the channel", zygote: "#!/bin/sh\nsleep 2 &\nexit 3\n",
			want: "exited before READY: exit status 3"},
		{name: "a zygote that is never ready", zygote: "#!/bin/sh\nexec sleep 600\n", timeout: 50 * time.Millisecond, want: "in time"},
		{name: "a canceled build", zygote: "#!/bin/sh\nexec sleep 600\n", canceled: true, want: context.Canceled.Error()},
		{name: "a zygote that does not execute", zygote: "not a program", want: "start zygote"},
		{name: "a dump that fails", zygote: readyZygote, fail: "no ptrace here", want: "no ptrace here"},
		{name: "a scratch directory that cannot be made", zygote: readyZygote, taken: "images.work", want: "not a directory"},
		{name: "an archive that cannot be written", zygote: readyZygote, taken: "images.tar/x", want: "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			zygote := filepath.Join(root, "zygote.sh")
			mustWrite(t, zygote, []byte(tc.zygote))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			out := filepath.Join(root, "out")
			if tc.taken != "" {
				mustMkdir(t, filepath.Dir(filepath.Join(out, tc.taken)))
				mustWrite(t, filepath.Join(out, tc.taken), nil)
			}
			fake := &buildCriu{fail: tc.fail}
			type result struct {
				d   string
				err error
			}
			k, pub := fleet(t)
			done := make(chan result, 1)
			go func() {
				d, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygote, Args: []string{"-x"}, Out: out, SealTo: pub,
					CRIU: criu.Options{Commander: fake}, ReadyTimeout: tc.timeout})
				done <- result{d, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Build hangs")
			}
			if tc.want != "" {
				if r.err == nil || !strings.Contains(r.err.Error(), tc.want) {
					t.Fatalf("Build = %s, %v; want an error about %q", r.d, r.err, tc.want)
				}
				return
			}
			if r.err != nil {
				t.Fatal(r.err)
			}
			cfg, err := artifact.ReadConfig(out)
			if err != nil || !cfg.HasImages() || cfg.Arch != runtime.GOARCH {
				t.Fatalf("config = %+v, %v", cfg, err)
			}
			if got := openedImages(t, out, k); got["pages-1.img"] != "pages\n" {
				t.Fatalf("images.tar holds %v", got)
			}
			args := strings.Join(fake.args, " ")
			if !strings.Contains(args, "--leave-running") || strings.Contains(args, "--external unix[") != tc.external {
				t.Fatalf("criu ran with %q; want --leave-running, external socket %v", args, tc.external)
			}
			if _, err := os.Stat(artifact.ImagesDir(out) + ".work"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the zygote's scratch directory is left: %v", err)
			}
		})
	}
}

// TestArtifactBuildWithCRIU checkpoints a real zygote with the real criu.
func TestArtifactBuildWithCRIU(t *testing.T) {
	ctx := context.Background()
	if err := (criu.Options{}).Available(ctx); err != nil {
		t.Skipf("criu: %v", err)
	}
	cases := []struct {
		name   string
		zygote string
	}{
		{name: "a ready zygote's pages are archived", zygote: readyZygote},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			zygote := filepath.Join(root, "zygote.sh")
			mustWrite(t, zygote, []byte(tc.zygote))
			out := filepath.Join(root, "out")
			k, pub := fleet(t)
			d, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygote, Out: out, SealTo: pub})
			if err != nil {
				t.Fatal(err)
			}
			got := openedImages(t, out, k)
			pages := 0
			for name := range got {
				if strings.HasPrefix(name, "pages-") {
					pages++
				}
			}
			if pages == 0 {
				t.Fatalf("images.tar holds no pages: %v", len(got))
			}
			if again, err := artifact.Reverify(ctx, out, d); err != nil || !again.HasImages() {
				t.Fatalf("Reverify = %+v, %v", again, err)
			}
			if err := artifact.UnpackImages(out, cfgOf(t, out), k); err != nil {
				t.Fatalf("UnpackImages: %v", err)
			}
		})
	}
}

func cfgOf(t *testing.T, dir string) artifact.Config {
	t.Helper()
	c, err := artifact.ReadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestArtifactHostInfo checks the parity facts against the kernel and a
// stand-in ldd on PATH, whose first line names the libc.
func TestArtifactHostInfo(t *testing.T) {
	osrelease, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ldd  string // the stand-in's script, "" for no ldd at all
		libc string
	}{
		{name: "glibc names itself", ldd: "#!/bin/sh\necho 'ldd (GNU libc) 2.36'\necho 'Copyright'\n", libc: "(gnu libc) 2.36"},
		{name: "an ldd that prints nothing", ldd: "#!/bin/sh\n", libc: "unknown"},
		{name: "an ldd that fails, as musl's does", ldd: "#!/bin/sh\necho 'musl libc' >&2\nexit 1\n", libc: "unknown"},
		{name: "no ldd", libc: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.ldd != "" {
				execFile(t, filepath.Join(dir, "ldd"), tc.ldd)
			}
			t.Setenv("PATH", dir)
			arch, kernel, libc := artifact.HostInfo()
			if arch != runtime.GOARCH || kernel != strings.TrimSpace(string(osrelease)) || libc != tc.libc {
				t.Fatalf("HostInfo = %s, %s, %q; want %s, %s, %q", arch, kernel, libc, runtime.GOARCH, osrelease, tc.libc)
			}
			if host := artifact.Host(); host.Libc != tc.libc {
				t.Fatalf("Host records libc %q, want %q", host.Libc, tc.libc)
			}
		})
	}
}
