//go:build !linux

package artifact_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// TestBuildImagesNeedLinux checks that off Linux a build runs no zygote:
// images and the smoke test both need Linux, and only a build without
// either succeeds.
func TestBuildImagesNeedLinux(t *testing.T) {
	_, pub := fleet(t)
	cases := []struct {
		name string
		opts artifact.BuildOptions
		want string // a substring of the error, "" for success
	}{
		{name: "a build with images", opts: artifact.BuildOptions{SealTo: pub}, want: "needs Linux"},
		{name: "a build without images smoke-tests the zygote", opts: artifact.BuildOptions{SkipImages: true}, want: "-no-smoke"},
		{name: "a build without images or smoke test", opts: artifact.BuildOptions{SkipImages: true, NoSmoke: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			c.opts.Zygote, c.opts.Out = filepath.Join(root, "z"), filepath.Join(root, "out")
			_, err := artifact.Build(context.Background(), c.opts)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Build = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "needs Linux") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Build = %v, want it to need Linux and mention %q", err, c.want)
			}
		})
	}
}
