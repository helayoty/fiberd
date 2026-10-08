package artifact_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// TestBuildRefuses covers what Build checks before it runs anything.
func TestBuildRefuses(t *testing.T) {
	cases := []struct {
		name string
		// opts builds the options from a directory the case may use.
		opts func(t *testing.T, root string) artifact.BuildOptions
		want error // nil when any error will do
	}{
		{name: "no zygote", opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Out: root}
		}},
		{name: "no output directory", opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z")}
		}},
		{name: "a missing zygote", want: os.ErrNotExist, opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: filepath.Join(root, "missing"), Out: filepath.Join(root, "out"), SkipImages: true}
		}},
		{name: "a zygote that is a directory", want: syscall.EISDIR, opts: func(_ *testing.T, root string) artifact.BuildOptions {
			return artifact.BuildOptions{Zygote: root, Out: filepath.Join(root, "out"), SkipImages: true}
		}},
		{name: "an output directory under a regular file", want: syscall.ENOTDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "z", "out"), SkipImages: true}
		}},
		{name: "a zygote that cannot be written", want: syscall.EISDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			writeFile(t, filepath.Join(root, "out", "zygote", "inner"), "")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "out"), SkipImages: true}
		}},
		{name: "a config that cannot be written", want: syscall.EISDIR, opts: func(t *testing.T, root string) artifact.BuildOptions {
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			writeFile(t, filepath.Join(root, "out", "config.json", "inner"), "")
			return artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Out: filepath.Join(root, "out"), SkipImages: true}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := artifact.Build(context.Background(), c.opts(t, t.TempDir()))
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("Build = %s, %v; want %v", d, err, c.want)
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
