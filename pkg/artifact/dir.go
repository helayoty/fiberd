package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// Directory artifacts: a flat directory of files pushed as one manifest
// with a titled layer per file. Parked deltas and zygote parent
// checkpoints travel this way; the manifest annotations carry what a
// home needs to decide before it pulls (size, parent hash, origin).
// A reference starting with file:// names a directory tree instead of a
// registry (see fileregistry.go); every function here takes either.

const (
	ArtifactTypeDelta  = "application/vnd.fiberd.delta.v1"
	ArtifactTypeParent = "application/vnd.fiberd.parent.v1"
	mediaTypeFile      = "application/vnd.fiberd.file.v1"

	AnnotationWBytes  = "io.fiberd.w_bytes"
	AnnotationParent  = "io.fiberd.parent_sha256"
	AnnotationHome    = "io.fiberd.home"
	AnnotationFence   = "io.fiberd.fence"
	AnnotationGrant   = "io.fiberd.grant_uid"
	AnnotationSession = "io.fiberd.session"
)

// PushDir uploads every regular file in dir (logs excluded) as the
// artifact at ref, with the annotations on the manifest. Returns the
// manifest digest.
func PushDir(ctx context.Context, dir, ref, artifactType string, annotations map[string]string, plainHTTP bool) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if IsFileRef(ref) {
		return filePushDir(dir, ref, artifactType, annotations)
	}
	fs, err := file.New(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = fs.Close() }()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasSuffix(e.Name(), ".log") && !strings.HasSuffix(e.Name(), ".tmp") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var layers []ocispec.Descriptor
	for _, n := range names {
		d, err := fs.Add(ctx, n, mediaTypeFile, n)
		if err != nil {
			return "", err
		}
		layers = append(layers, d)
	}
	desc, err := oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, artifactType,
		oras.PackManifestOptions{Layers: layers, ManifestAnnotations: annotations})
	if err != nil {
		return "", err
	}
	repo, tag, err := repository(ref, plainHTTP)
	if err != nil {
		return "", err
	}
	if tag == "" {
		tag = desc.Digest.String()
	}
	if err := fs.Tag(ctx, desc, tag); err != nil {
		return "", err
	}
	if _, err := oras.Copy(ctx, fs, tag, repo, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("artifact: push %s: %w", ref, err)
	}
	return desc.Digest.String(), nil
}

// Located describes an artifact found in a registry without pulling it.
type Located struct {
	Digest       string
	ArtifactType string
	Annotations  map[string]string
}

// Resolve fetches only the manifest at ref (repo:tag or repo@digest).
// found is false when the registry has nothing there.
func Resolve(ctx context.Context, ref string, plainHTTP bool) (Located, bool, error) {
	if IsFileRef(ref) {
		return fileResolve(ref)
	}
	repo, target, err := repository(ref, plainHTTP)
	if err != nil {
		return Located{}, false, err
	}
	desc, err := repo.Resolve(ctx, target)
	if err != nil {
		if isNotFound(err) {
			return Located{}, false, nil
		}
		return Located{}, false, fmt.Errorf("artifact: resolve %s: %w", ref, err)
	}
	rc, err := repo.Manifests().Fetch(ctx, desc)
	if err != nil {
		return Located{}, false, err
	}
	defer func() { _ = rc.Close() }()
	mb, err := content.ReadAll(rc, desc)
	if err != nil {
		return Located{}, false, err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Located{}, false, err
	}
	return Located{Digest: desc.Digest.String(), ArtifactType: m.ArtifactType, Annotations: m.Annotations}, true, nil
}

// PullDir downloads the artifact at ref into dst (files land under their
// titles) and returns the manifest digest.
func PullDir(ctx context.Context, ref, dst string, plainHTTP bool) (string, error) {
	dst, err := filepath.Abs(dst)
	if err != nil {
		return "", err
	}
	if IsFileRef(ref) {
		return filePullDir(ref, dst)
	}
	repo, target, err := repository(ref, plainHTTP)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	fs, err := file.New(dst)
	if err != nil {
		return "", err
	}
	defer func() { _ = fs.Close() }()
	desc, err := oras.Copy(ctx, repo, target, fs, target, oras.DefaultCopyOptions)
	if err != nil {
		return "", fmt.Errorf("artifact: pull %s: %w", ref, err)
	}
	return desc.Digest.String(), nil
}

// Delete removes the manifest at ref (a tag or digest). Registries must
// allow deletes (registry:2: REGISTRY_STORAGE_DELETE_ENABLED=true). A
// missing manifest is not an error: the goal is that it be gone. A tag
// is deleted as a tag first (some registries keep tag entries when the
// manifest is deleted by digest), then the manifest by digest.
func Delete(ctx context.Context, ref string, plainHTTP bool) error {
	if IsFileRef(ref) {
		return fileDelete(ref)
	}
	repo, target, err := repository(ref, plainHTTP)
	if err != nil {
		return err
	}
	desc, err := repo.Resolve(ctx, target)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	isTag := !strings.HasPrefix(target, "sha256:")
	if isTag {
		// Registries differ: some delete tags by reference, registry:2
		// refuses (400) and instead drops tags when the manifest goes.
		if err := deleteByReference(ctx, repo, target, plainHTTP); err != nil && !isNotFound(err) && !errors.Is(err, errUntagUnsupported) {
			return fmt.Errorf("artifact: untag %s: %w", ref, err)
		}
	}
	if err := repo.Manifests().Delete(ctx, desc); err != nil && !isNotFound(err) {
		return fmt.Errorf("artifact: delete %s: %w", ref, err)
	}
	if isTag {
		// Either path must have made the tag stop pointing at the manifest.
		if again, err := repo.Resolve(ctx, target); err == nil && again.Digest == desc.Digest {
			return fmt.Errorf("artifact: %s still resolves after delete; the registry does not support deletion", ref)
		}
	}
	return nil
}

var errUntagUnsupported = errors.New("registry does not delete by tag")

// deleteByReference issues DELETE /v2/<name>/manifests/<tag>, which the
// distribution API allows for tags where the registry supports it.
func deleteByReference(ctx context.Context, repo *remote.Repository, tag string, plainHTTP bool) error {
	scheme := "https"
	if plainHTTP {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, repo.Reference.Registry, repo.Reference.Repository, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	client := repo.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return errdef.ErrNotFound
	case http.StatusBadRequest, http.StatusMethodNotAllowed:
		return errUntagUnsupported
	default:
		return fmt.Errorf("http %d", resp.StatusCode)
	}
}

// isNotFound recognises a missing tag or manifest however the registry
// and client phrase it.
func isNotFound(err error) bool {
	if errors.Is(err, errdef.ErrNotFound) {
		return true
	}
	var ec *errcode.ErrorResponse
	if errors.As(err, &ec) && ec.StatusCode == 404 {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// Repository is the remote.Repository for callers that need it directly.
func Repository(ref string, plainHTTP bool) (*remote.Repository, string, error) {
	return repository(ref, plainHTTP)
}
