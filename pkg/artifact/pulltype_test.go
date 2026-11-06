package artifact_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/Azure/fiberd/pkg/artifact"
)

// pushTyped pushes the files of dir as a zygote artifact to reg, each
// layer under the media type types names, as a hand-made manifest with
// Pack's annotations, so it is the manifest Pack writes exactly when the
// types are the ones Pack gives.
func pushTyped(t *testing.T, reg, dir string, types map[string]string) {
	t.Helper()
	ctx := context.Background()
	cfg, err := artifact.ReadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := file.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fs.Close() }()
	var layers []ocispec.Descriptor
	for _, n := range []string{"zygote", "config.json", "images.tar"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			continue
		}
		d, err := fs.Add(ctx, n, types[n], n)
		if err != nil {
			t.Fatal(err)
		}
		layers = append(layers, d)
	}
	desc, err := oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, artifact.ArtifactType, oras.PackManifestOptions{Layers: layers,
		ManifestAnnotations: map[string]string{ocispec.AnnotationCreated: cfg.BuiltAt.UTC().Format(time.RFC3339), "io.fiberd.arch": cfg.Arch}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Tag(ctx, desc, "t"); err != nil {
		t.Fatal(err)
	}
	repo, err := remote.NewRepository(strings.TrimPrefix(reg, "http://") + "/z")
	if err != nil {
		t.Fatal(err)
	}
	repo.PlainHTTP = true
	if _, err := oras.Copy(ctx, fs, "t", repo, "t", oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}
}

// TestPullHoldsTheImagesTypeToTheFormat checks that a pull takes a
// manifest only as Pack writes it, so a layer's media type that its
// config's format does not give it is refused both ways, and a home never
// opens CRIU images as a snapshot, nor a snapshot as CRIU images.
func TestPullHoldsTheImagesTypeToTheFormat(t *testing.T) {
	criu, _, _ := imagesArtifact(t)
	snap, _, _ := hyperlightArtifact(t, snapshotTree(t))
	cases := []struct {
		name  string
		dir   string
		types map[string]string
		ok    bool
	}{
		{name: "CRIU images under the types Pack gives them", dir: criu, ok: true,
			types: map[string]string{"zygote": artifact.MediaTypeBinary, "config.json": artifact.MediaTypeConfig, "images.tar": artifact.MediaTypeImages}},
		{name: "a Hyperlight snapshot under the types Pack gives it", dir: snap, ok: true,
			types: map[string]string{"config.json": artifact.MediaTypeConfig, "images.tar": artifact.MediaTypeHyperlight}},
		{name: "CRIU images under the Hyperlight media type", dir: criu,
			types: map[string]string{"zygote": artifact.MediaTypeBinary, "config.json": artifact.MediaTypeConfig, "images.tar": artifact.MediaTypeHyperlight}},
		{name: "a Hyperlight snapshot under the CRIU media type", dir: snap,
			types: map[string]string{"config.json": artifact.MediaTypeConfig, "images.tar": artifact.MediaTypeImages}},
		{name: "a zygote under the config's media type", dir: criu,
			types: map[string]string{"zygote": artifact.MediaTypeConfig, "config.json": artifact.MediaTypeConfig, "images.tar": artifact.MediaTypeImages}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := newRegistry(t)
			pushTyped(t, reg, tc.dir, tc.types)
			cfg, err := artifact.Pull(context.Background(), reg+"/z:t", filepath.Join(t.TempDir(), "pulled"))
			if tc.ok {
				if err != nil || cfg.Digest == "" {
					t.Fatalf("Pull = %+v, %v", cfg, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "packs to") {
				t.Fatalf("Pull = %v, want the manifest refused", err)
			}
		})
	}
}
