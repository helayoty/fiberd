package artifact_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// fakePlatform is what fakeHost reports as this host.
var fakePlatform = artifact.Platform{Arch: runtime.GOARCH, Kernel: "6.1.0-test", Libc: "(gnu libc) 2.36"}

// fakeHost stands in for the host facts Build and Host record, since the
// real ones run ldd on Linux.
func fakeHost(t *testing.T) {
	t.Helper()
	t.Cleanup(artifact.SetHostInfo(func() (string, string, string) {
		return fakePlatform.Arch, fakePlatform.Kernel, fakePlatform.Libc
	}))
}

// TestBuildRefuses covers what Build checks before it runs anything.
func TestBuildRefuses(t *testing.T) {
	fakeHost(t)
	cases := []struct {
		name string
		// opts builds the options from a directory the case may use.
		opts     func(t *testing.T, root string) artifact.BuildOptions
		want     error  // nil when any error will do
		wantText string // a substring of the error, when set
	}{
		{name: "no zygote", opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Out: root}
		}},
		{name: "no output directory", opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z")}
		}},
		// Regression: a build with images packed them in the clear. Now
		// it refuses before it runs anything, without a key to seal to.
		{name: "images without a fleet key to seal them to", wantText: "-seal-to", opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n: > "+filepath.Join(root, "ran")+"\n")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "out")}
		}},
		{name: "a missing zygote", want: os.ErrNotExist, opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: filepath.Join(root, "missing"), Out: filepath.Join(root, "out"), SkipImages: true, NoSmoke: true}
		}},
		{name: "a zygote that is a directory", want: syscall.EISDIR, opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: root, Out: filepath.Join(root, "out"), SkipImages: true, NoSmoke: true}
		}},
		{name: "an output directory under a regular file", want: syscall.ENOTDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "z", "out"), SkipImages: true, NoSmoke: true}
		}},
		{name: "a zygote that cannot be written", want: syscall.EISDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			writeFile(t, filepath.Join(root, "out", "zygote", "inner"), "")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "out"), SkipImages: true, NoSmoke: true}
		}},
		{name: "a config that cannot be written", want: syscall.EISDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			writeFile(t, filepath.Join(root, "out", "config.json", "inner"), "")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "out"), SkipImages: true, NoSmoke: true}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			d, err := artifact.Build(context.Background(), c.opts(t, root))
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.wantText) {
				t.Fatalf("Build = %s, %v; want %v %q", d, err, c.want, c.wantText)
			}
			if _, err := os.Stat(filepath.Join(root, "ran")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused build ran the zygote: %v", err)
			}
		})
	}
}

func TestPack(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, dir string)
		want string // a substring of the error, "" for success
	}{
		{name: "a zygote and its config pack, without images", want: ""},
		{name: "a missing config", want: "config.json",
			edit: func(t *testing.T, dir string) { remove(t, filepath.Join(dir, "config.json")) }},
		{name: "a config that is not JSON", want: "artifact: config.json",
			edit: func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "config.json"), "[") }},
		{name: "a missing zygote", want: "missing zygote",
			edit: func(t *testing.T, dir string) { remove(t, artifact.ZygotePath(dir)) }},
		// Regression: images.tar was packed whatever it held.
		{name: "images in the clear", want: "without a seal",
			edit: func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "images.tar"), "plain pages") }},
		{name: "images in the clear under a config that names a seal", want: "is not sealed",
			edit: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "images.tar"), "plain pages")
				editConfig(t, dir, func(c *artifact.Config) { c.Images = &artifact.ImagesSeal{SHA256: strings.Repeat("0", 64)} })
			}},
		{name: "a config naming images that are not there", want: "no images.tar",
			edit: func(t *testing.T, dir string) {
				editConfig(t, dir, func(c *artifact.Config) { c.Images = &artifact.ImagesSeal{SHA256: strings.Repeat("0", 64)} })
			}},
		{name: "sealed images pack", edit: func(t *testing.T, dir string) {
			_, pub := fleet(t)
			s := sealedImagesTar(t, dir, map[string]string{"pages-1.img": "pages"}, pub)
			editConfig(t, dir, func(c *artifact.Config) { c.Images = &s })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := zygoteDir(t)
			if c.edit != nil {
				c.edit(t, dir)
			}
			d, err := artifact.Pack(context.Background(), dir)
			recorded, rerr := artifact.ReadDigest(dir)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Pack = %s, %v; want an error about %q", d, err, c.want)
				}
				if !errors.Is(rerr, os.ErrNotExist) {
					t.Fatalf("a failed pack recorded %q (%v)", recorded, rerr)
				}
				return
			}
			if err != nil || rerr != nil || recorded != d || !strings.HasPrefix(d, "sha256:") {
				t.Fatalf("Pack = %s, %v; recorded %s, %v", d, err, recorded, rerr)
			}
		})
	}
}
