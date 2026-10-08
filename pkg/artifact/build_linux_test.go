//go:build linux

package artifact_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// fakeCRIU stands in for criu dump. It records its arguments and writes
// one page image into the -D directory, or fails when told to.
const fakeCRIU = `#!/bin/sh
dir=""; prev=""
for a in "$@"; do [ "$prev" = "-D" ] && dir="$a"; prev="$a"; done
[ -n "$FAIL" ] && { echo "$FAIL" >&2; exit 1; }
echo "$@" > "$dir/args"
echo pages > "$dir/pages-1.img"
`

// Zygotes speak on fd 3, as a home's do. The second moves its channel
// off fd 3 before it is ready.
const (
	readyZygote   = "#!/bin/sh\necho READY >&3\nexec sleep 600\n"
	closingZygote = "#!/bin/sh\nexec 4>&3 3>&-\necho READY >&4\nexec sleep 600\n"
)

// TestBuildCheckpoint runs Build's checkpoint against a fake criu, so
// the zygote handshake and the dump arguments are checked on any Linux.
func TestBuildCheckpoint(t *testing.T) {
	cases := []struct {
		name     string
		zygote   string
		fail     string // the fake criu fails with this
		timeout  time.Duration
		canceled bool
		want     string // a substring of the error; "" for success
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
			want: "exited before READY"},
		{name: "a zygote that is never ready", zygote: "#!/bin/sh\nexec sleep 600\n", timeout: 50 * time.Millisecond, want: "in time"},
		{name: "a canceled build", zygote: "#!/bin/sh\nexec sleep 600\n", canceled: true, want: context.Canceled.Error()},
		{name: "a zygote that does not execute", zygote: "not a program", want: "start zygote"},
		{name: "a dump that fails", zygote: readyZygote, fail: "no ptrace here", want: "no ptrace here"},
		{name: "a scratch directory that cannot be made", zygote: readyZygote, taken: "images.work", want: "not a directory"},
		{name: "an archive that cannot be written", zygote: readyZygote, taken: "images.tar/x", want: "is a directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "criu")
			writeFile(t, bin, fakeCRIU)
			if err := os.Chmod(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FAIL", c.fail)
			zygote := filepath.Join(root, "zygote.sh")
			writeFile(t, zygote, c.zygote)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.canceled {
				cancel()
			}
			out := filepath.Join(root, "out")
			if c.taken != "" {
				writeFile(t, filepath.Join(out, c.taken), "")
			}
			type result struct {
				d   string
				err error
			}
			done := make(chan result, 1)
			go func() {
				d, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygote, Args: []string{"-x"}, Out: out,
					CRIU: criu.Options{Bin: bin}, ReadyTimeout: c.timeout})
				done <- result{d, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Build hangs")
			}
			d, err := r.d, r.err
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Build = %s, %v; want an error about %q", d, err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := artifact.ReadConfig(out)
			if err != nil || !cfg.HasImages || cfg.Arch != runtime.GOARCH {
				t.Fatalf("config = %+v, %v", cfg, err)
			}
			if got := tarEntries(t, filepath.Join(out, "images.tar")); got["pages-1.img"] != "pages\n" {
				t.Fatalf("images.tar holds %v", got)
			}
			args, _ := os.ReadFile(filepath.Join(artifact.ImagesDir(out), "args"))
			if !strings.Contains(string(args), "--leave-running") || strings.Contains(string(args), "--external unix[") != c.external {
				t.Fatalf("criu ran with %q; want --leave-running, external socket %v", args, c.external)
			}
			if _, err := os.Stat(artifact.ImagesDir(out) + ".work"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the zygote's scratch directory is left: %v", err)
			}
		})
	}
}

// TestBuildWithCRIU checkpoints a real zygote where criu works.
func TestBuildWithCRIU(t *testing.T) {
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
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			zygote := filepath.Join(root, "zygote.sh")
			writeFile(t, zygote, c.zygote)
			out := filepath.Join(root, "out")
			d, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygote, Out: out})
			if err != nil {
				t.Fatal(err)
			}
			got := tarEntries(t, filepath.Join(out, "images.tar"))
			pages := 0
			for name := range got {
				if strings.HasPrefix(name, "pages-") {
					pages++
				}
			}
			if pages == 0 {
				t.Fatalf("images.tar holds no pages: %v", len(got))
			}
			if again, err := artifact.Reverify(ctx, out, d); err != nil || !again.HasImages {
				t.Fatalf("Reverify = %+v, %v", again, err)
			}
		})
	}
}

// TestHostInfo checks the parity facts against the kernel and a stand-in
// ldd, whose first line names the libc.
func TestHostInfo(t *testing.T) {
	osrelease, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ldd  string // the stand-in's script; "" for no ldd at all
		libc string
	}{
		{name: "glibc names itself", ldd: "#!/bin/sh\necho 'ldd (GNU libc) 2.36'\necho 'Copyright'\n", libc: "(gnu libc) 2.36"},
		{name: "an ldd that prints nothing", ldd: "#!/bin/sh\n", libc: "unknown"},
		{name: "an ldd that fails, as musl's does", ldd: "#!/bin/sh\necho 'musl libc' >&2\nexit 1\n", libc: "unknown"},
		{name: "no ldd", libc: "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.ldd != "" {
				writeFile(t, filepath.Join(dir, "ldd"), c.ldd)
				if err := os.Chmod(filepath.Join(dir, "ldd"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", dir)
			arch, kernel, libc := artifact.HostInfo()
			if arch != runtime.GOARCH || kernel != strings.TrimSpace(string(osrelease)) || libc != c.libc {
				t.Fatalf("HostInfo = %s, %s, %q; want %s, %s, %q", arch, kernel, libc, runtime.GOARCH, osrelease, c.libc)
			}
		})
	}
}
