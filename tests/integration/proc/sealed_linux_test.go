//go:build linux && integration

package proctest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// sealMagic is how every sealed file starts.
const sealMagic = "fiberd-seal-v1\n"

// fleetPub is the fleet's public wrap key, derived from the master every
// test home holds. Authors seal images to it.
func fleetPub(t *testing.T) *artifact.WrapPublicKey {
	t.Helper()
	w, err := artifact.DeriveWrapKey(deltaKeys.Seal)
	if err != nil {
		t.Fatal(err)
	}
	return w.Public()
}

// buildArtifact builds the reference zygote into out with its CRIU
// images sealed to the fleet, as zygotectl build -seal-to does.
func buildArtifact(t *testing.T, out string) string {
	t.Helper()
	digest, err := artifact.Build(context.Background(), artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out, SealTo: fleetPub(t)})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	return digest
}

// diskRegistry is an OCI registry in this process that keeps every blob
// as a file under the returned directory, so a test can read what the
// registry holds.
func diskRegistry(t *testing.T) (url, blobs string) {
	t.Helper()
	blobs = t.TempDir()
	srv := httptest.NewServer(registry.New(registry.WithBlobHandler(registry.NewDiskBlobHandler(blobs)), registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return srv.URL, blobs
}

// plainBlobs are the sha256s of what an artifact in out may hold in the
// clear: the zygote, its config, and the empty OCI config blob. Code and
// config, never memory.
func plainBlobs(t *testing.T, out string) map[string]bool {
	t.Helper()
	empty := sha256.Sum256([]byte("{}"))
	allowed := map[string]bool{hex.EncodeToString(empty[:]): true}
	for _, f := range []string{artifact.ZygotePath(out), filepath.Join(out, "config.json")} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		allowed[hex.EncodeToString(sum[:])] = true
	}
	return allowed
}

// requireSealed reads every content file under root, the blobs of a disk
// registry or the files/ of a file registry, and fails on one that is
// neither sealed nor in allowed. It returns how many sealed files it saw.
func requireSealed(t *testing.T, root string, allowed map[string]bool) int {
	t.Helper()
	sealed := 0
	err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		// A file registry keeps metadata beside the files: the manifest
		// and the tags.
		if strings.Contains(path, string(filepath.Separator)+"tags"+string(filepath.Separator)) || e.Name() == "manifest.json" && filepath.Base(filepath.Dir(path)) != "files" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(b), sealMagic) {
			sealed++
			return nil
		}
		sum := sha256.Sum256(b)
		if !allowed[hex.EncodeToString(sum[:])] {
			t.Errorf("%s (%d bytes) is in the registry in the clear", path, len(b))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
