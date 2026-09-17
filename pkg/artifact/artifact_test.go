package artifact_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// A registry in this process: go-containerregistry's in-memory
// implementation of the OCI distribution API.
func newRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

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
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: src, Args: []string{"--heap-mb", "8"}, Out: out, SkipImages: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest = %q", digest)
	}
	cfg, err := artifact.ReadConfig(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Arch == "" || cfg.ZygoteSHA256 == "" || cfg.HasImages || len(cfg.Args) != 2 {
		t.Fatalf("config = %+v", cfg)
	}
	// Packing again is deterministic.
	again, err := artifact.Pack(ctx, out)
	if err != nil || again != digest {
		t.Fatalf("repack digest = %s (%v), want %s", again, err, digest)
	}

	reg := newRegistry(t)
	ref := reg + "/zygotes/test:v1"
	pushed, err := artifact.Push(ctx, out, ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if pushed != digest {
		t.Fatalf("push digest = %s, want the packed digest %s", pushed, digest)
	}

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

	// Pull by tag works too; a wrong digest is refused by the transfer.
	if _, err := artifact.Pull(ctx, ref, filepath.Join(t.TempDir(), "bytag"), true); err != nil {
		t.Fatalf("pull by tag: %v", err)
	}
	bogus := "sha256:" + strings.Repeat("0", 64)
	if _, err := artifact.Pull(ctx, reg+"/zygotes/test@"+bogus, filepath.Join(t.TempDir(), "bogus"), true); err == nil {
		t.Fatal("pull of a nonexistent digest succeeded")
	}
}
