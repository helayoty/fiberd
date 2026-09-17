package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A delta published by one home (a file registry standing in for it)
// exported as files, then imported by another home under a new session
// name: the second registry resolves the new name, with the parent, and
// the first no longer holds the session.
func TestExportImportDelta(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "a"), HomeID: "home-a"}
	b := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "b"), HomeID: "home-b"}
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
	g2 := core.Grant{UID: "g2", TemplateDigest: "sha256:tmpl"} // another grant, same domain

	parentSHA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	repo := domainRepoFor(a.DeltaRegistry, g)
	write(t, filepath.Join(root, "parent"), map[string]string{"pages-1.img": "template pages"})
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(parentSHA), artifact.ArtifactTypeParent,
		map[string]string{artifact.AnnotationParent: parentSHA}, false); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "delta"), map[string]string{"pages-1.img": "dirty pages", "manifest.json": `{"fence":"g1/1/1"}`, "dump.log": "x"})
	ann := map[string]string{artifact.AnnotationSession: "S", artifact.AnnotationGrant: "g1", artifact.AnnotationHome: "home-a",
		artifact.AnnotationParent: parentSHA, artifact.AnnotationWBytes: "11", "io.fiberd.arch": "arm64"}
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "delta"), repo+":"+sessionTag("S"), artifact.ArtifactTypeDelta, ann, false); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(root, "out")
	files, err := ExportDelta(ctx, a, g, "S", out)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	want := map[string]bool{ExportDeltaFile: true, ExportParentFile: true, ExportInfoFile: true}
	for _, f := range files {
		if !want[f] {
			t.Errorf("unexpected export file %s", f)
		}
		delete(want, f)
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing export files: %v", want)
	}
	if _, found, _ := artifact.Resolve(ctx, repo+":"+sessionTag("S"), false); found {
		t.Fatal("the exporting home still holds the session")
	}
	if _, err := ExportDelta(ctx, a, g, "S", out); err == nil {
		t.Fatal("exporting an unpublished session must fail")
	}

	if err := ImportDelta(ctx, b, g2, "S2", out); err != nil {
		t.Fatalf("import: %v", err)
	}
	repoB := domainRepoFor(b.DeltaRegistry, g2)
	loc, found, err := artifact.Resolve(ctx, repoB+":"+sessionTag("S2"), false)
	if err != nil || !found {
		t.Fatalf("imported session not found: %v", err)
	}
	if loc.ArtifactType != artifact.ArtifactTypeDelta || loc.Annotations[artifact.AnnotationSession] != "S2" ||
		loc.Annotations[artifact.AnnotationGrant] != "g2" || loc.Annotations[artifact.AnnotationHome] != "home-b" ||
		loc.Annotations[artifact.AnnotationParent] != parentSHA || loc.Annotations[artifact.AnnotationWBytes] != "11" ||
		loc.Annotations["io.fiberd.arch"] != "arm64" {
		t.Fatalf("imported annotations %v", loc.Annotations)
	}
	ploc, found, err := artifact.Resolve(ctx, repoB+":"+parentTag(parentSHA), false)
	if err != nil || !found || ploc.ArtifactType != artifact.ArtifactTypeParent {
		t.Fatalf("parent not imported: found=%v %+v %v", found, ploc, err)
	}
	dst := filepath.Join(root, "pulled")
	if _, err := artifact.PullDir(ctx, repoB+"@"+loc.Digest, dst, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "pages-1.img")); string(got) != "dirty pages" {
		t.Fatalf("pulled delta pages = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "dump.log")); err == nil {
		t.Fatal("logs travelled")
	}
	// Importing again (the same snapshot restored a second time, under a
	// third name) reuses the parent already there.
	if err := ImportDelta(ctx, b, g2, "S3", out); err != nil {
		t.Fatalf("second import: %v", err)
	}
}

func TestExportDeltaNeedsRegistry(t *testing.T) {
	if _, err := ExportDelta(context.Background(), Config{}, core.Grant{}, "S", t.TempDir()); err == nil {
		t.Fatal("want an error without a registry")
	}
	if err := ImportDelta(context.Background(), Config{}, core.Grant{}, "S", t.TempDir()); err == nil {
		t.Fatal("want an error without a registry")
	}
}
