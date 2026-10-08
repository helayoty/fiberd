//go:build !linux

package artifact_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

func TestBuildImagesNeedLinux(t *testing.T) {
	cases := []struct {
		name string
		opts artifact.BuildOptions
	}{
		{name: "a build with images", opts: artifact.BuildOptions{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\n")
			c.opts.Zygote, c.opts.Out = filepath.Join(root, "z"), filepath.Join(root, "out")
			if _, err := artifact.Build(context.Background(), c.opts); err == nil || !strings.Contains(err.Error(), "needs Linux") {
				t.Fatalf("Build = %v, want it to need Linux", err)
			}
		})
	}
}
