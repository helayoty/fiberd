package artifact

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileRegistryRoundTrip(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := filepath.Join(root, "src")
	writeFiles(t, src, map[string]string{"pages-1.img": "pages", "manifest.json": "{}", "dump.log": "noise"})
	ref := FileScheme + filepath.Join(root, "reg", "tmpl-abcd") + ":s-1234"
	ann := map[string]string{AnnotationSession: "S", AnnotationWBytes: "5"}

	digest, err := PushDir(ctx, src, ref, ArtifactTypeDelta, ann, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	loc, found, err := Resolve(ctx, ref, false)
	if err != nil || !found {
		t.Fatalf("resolve: found=%v err=%v", found, err)
	}
	if loc.Digest != digest || loc.ArtifactType != ArtifactTypeDelta || loc.Annotations[AnnotationSession] != "S" {
		t.Fatalf("resolved %+v, want digest %s", loc, digest)
	}
	// The same content pushed again is the same digest (idempotent), and
	// a digest reference resolves too.
	if again, err := PushDir(ctx, src, ref, ArtifactTypeDelta, ann, false); err != nil || again != digest {
		t.Fatalf("second push: %s %v, want %s", again, err, digest)
	}
	byDigest := FileScheme + filepath.Join(root, "reg", "tmpl-abcd") + "@" + digest
	if _, found, err := Resolve(ctx, byDigest, false); err != nil || !found {
		t.Fatalf("resolve by digest: found=%v err=%v", found, err)
	}

	dst := filepath.Join(root, "dst")
	if got, err := PullDir(ctx, byDigest, dst, false); err != nil || got != digest {
		t.Fatalf("pull: %s %v", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "pages-1.img")); err != nil || string(b) != "pages" {
		t.Fatalf("pulled pages-1.img = %q %v", b, err)
	}
	// The artifact's own manifest.json is a file like any other; the
	// registry's bookkeeping must not shadow it.
	if b, err := os.ReadFile(filepath.Join(dst, "manifest.json")); err != nil || string(b) != "{}" {
		t.Fatalf("pulled manifest.json = %q %v, want the pushed file", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "dump.log")); err == nil {
		t.Fatal("logs must not travel")
	}

	// Delete by tag drops the tag and the content nothing else points at.
	if err := Delete(ctx, ref, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := Resolve(ctx, ref, false); found {
		t.Fatal("tag still resolves after delete")
	}
	if _, found, _ := Resolve(ctx, byDigest, false); found {
		t.Fatal("content still resolves after its only tag was deleted")
	}
	if err := Delete(ctx, ref, false); err != nil {
		t.Fatalf("deleting a missing tag must be fine: %v", err)
	}
}

func TestFileRegistryTwoTagsShareContent(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := filepath.Join(root, "src")
	writeFiles(t, src, map[string]string{"a": "1"})
	repo := FileScheme + filepath.Join(root, "reg", "r")
	d1, err := PushDir(ctx, src, repo+":one", ArtifactTypeParent, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := PushDir(ctx, src, repo+":two", ArtifactTypeParent, nil, false)
	if err != nil || d1 != d2 {
		t.Fatalf("same content, different digests: %s %s %v", d1, d2, err)
	}
	if err := Delete(ctx, repo+":one", false); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := Resolve(ctx, repo+":two", false); !found {
		t.Fatal("deleting one tag must keep content another tag points at")
	}
	if _, found, _ := Resolve(ctx, repo+":one", false); found {
		t.Fatal("deleted tag still resolves")
	}
}

func TestFileRefParsing(t *testing.T) {
	cases := []struct {
		ref, repo, target string
		bad               bool
	}{
		{ref: "file:///r/x/y:tag", repo: "/r/x/y", target: "tag"},
		{ref: "file:///r/x/y@sha256:ab", repo: "/r/x/y", target: "sha256:ab"},
		{ref: "file:///r/x/y", repo: "/r/x/y"},
		{ref: "file://rel/x:tag", bad: true},
		{ref: "file:///r/x:..", bad: true},
	}
	for _, c := range cases {
		repo, target, err := fileRef(c.ref)
		if c.bad {
			if err == nil {
				t.Errorf("%s: want an error", c.ref)
			}
			continue
		}
		if err != nil || repo != c.repo || target != c.target {
			t.Errorf("%s: got %q %q %v, want %q %q", c.ref, repo, target, err, c.repo, c.target)
		}
	}
}
