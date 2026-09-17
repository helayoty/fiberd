package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A file registry: the directory-artifact operations (PushDir, Resolve,
// PullDir, Delete) over a directory tree instead of an OCI registry, for
// homes that share a filesystem, and for environments that move
// snapshots themselves and hand fiberd a directory to publish into and
// claim from (see host.ExportDelta / host.ImportDelta). A reference is
//
//	file://<root>/<repository>:<tag>       or
//	file://<root>/<repository>@sha256:<hex>
//
// and the tree under <root>/<repository> is
//
//	blobs/sha256/<hex>/manifest.json   what was pushed (type, annotations, files)
//	blobs/sha256/<hex>/files/<file>... the artifact's files
//	tags/<tag>                         the digest the tag points at
//
// The digest is the sha256 of the manifest (artifact type, annotations,
// and every file's name and sha256), so the same content pushed twice
// resolves to the same digest, as it would in an OCI registry.

const FileScheme = "file://"

// IsFileRef reports whether ref names a file registry.
func IsFileRef(ref string) bool { return strings.HasPrefix(ref, FileScheme) }

type storedManifest struct {
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Files        []fileEntry       `json:"files"`
}

type fileEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// fileRef splits file://<root>/<repo>[:<tag>|@<digest>] into the
// repository directory and the target (tag, digest, or empty).
func fileRef(ref string) (repoDir, target string, err error) {
	name := strings.TrimPrefix(ref, FileScheme)
	if i := strings.Index(name, "@"); i >= 0 {
		name, target = name[:i], name[i+1:]
	} else if i := strings.LastIndex(name, ":"); i >= 0 && !strings.Contains(name[i+1:], "/") && strings.Contains(name[:i], "/") {
		name, target = name[:i], name[i+1:]
	}
	if name == "" || !filepath.IsAbs(name) {
		return "", "", fmt.Errorf("artifact: file reference %q needs an absolute path", ref)
	}
	if strings.Contains(target, "/") || strings.Contains(target, "..") {
		return "", "", fmt.Errorf("artifact: bad target in %q", ref)
	}
	return filepath.Clean(name), target, nil
}

func blobDir(repoDir, digest string) string {
	return filepath.Join(repoDir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

func tagFile(repoDir, tag string) string { return filepath.Join(repoDir, "tags", tag) }

// resolveTarget turns a tag or digest into a digest.
func resolveTarget(repoDir, target string) (string, bool, error) {
	if strings.HasPrefix(target, "sha256:") {
		if _, err := os.Stat(filepath.Join(blobDir(repoDir, target), "manifest.json")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", false, nil
			}
			return "", false, err
		}
		return target, true, nil
	}
	b, err := os.ReadFile(tagFile(repoDir, target))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	d := strings.TrimSpace(string(b))
	if _, err := os.Stat(filepath.Join(blobDir(repoDir, d), "manifest.json")); err != nil {
		return "", false, nil // a dangling tag is no tag
	}
	return d, true, nil
}

func filePushDir(dir, ref, artifactType string, annotations map[string]string) (string, error) {
	repoDir, tag, err := fileRef(ref)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	m := storedManifest{ArtifactType: artifactType, Annotations: annotations}
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasSuffix(e.Name(), ".log") || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		sum, err := fileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		info, err := e.Info()
		if err != nil {
			return "", err
		}
		m.Files = append(m.Files, fileEntry{Name: e.Name(), SHA256: sum, Size: info.Size()})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	mb, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(mb)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	bd := blobDir(repoDir, digest)
	if _, err := os.Stat(filepath.Join(bd, "manifest.json")); err != nil {
		// New content: copy into a staging directory, then rename into place.
		tmp := bd + ".push"
		_ = os.RemoveAll(tmp)
		if err := os.MkdirAll(filepath.Join(tmp, "files"), 0o755); err != nil {
			return "", err
		}
		for _, f := range m.Files {
			if err := copyFile(filepath.Join(dir, f.Name), filepath.Join(tmp, "files", f.Name), 0o644); err != nil {
				_ = os.RemoveAll(tmp)
				return "", err
			}
		}
		if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), mb, 0o644); err != nil {
			_ = os.RemoveAll(tmp)
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(bd), 0o755); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, bd); err != nil {
			_ = os.RemoveAll(tmp)
			if _, again := os.Stat(filepath.Join(bd, "manifest.json")); again != nil {
				return "", err
			}
		}
	}
	if tag != "" && !strings.HasPrefix(tag, "sha256:") {
		if err := os.MkdirAll(filepath.Dir(tagFile(repoDir, tag)), 0o755); err != nil {
			return "", err
		}
		tmp := tagFile(repoDir, tag) + ".tmp"
		if err := os.WriteFile(tmp, []byte(digest+"\n"), 0o644); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, tagFile(repoDir, tag)); err != nil {
			return "", err
		}
	}
	return digest, nil
}

func fileResolve(ref string) (Located, bool, error) {
	repoDir, target, err := fileRef(ref)
	if err != nil {
		return Located{}, false, err
	}
	digest, found, err := resolveTarget(repoDir, target)
	if err != nil || !found {
		return Located{}, false, err
	}
	m, err := readFileManifest(repoDir, digest)
	if err != nil {
		return Located{}, false, err
	}
	return Located{Digest: digest, ArtifactType: m.ArtifactType, Annotations: m.Annotations}, true, nil
}

func readFileManifest(repoDir, digest string) (storedManifest, error) {
	var m storedManifest
	b, err := os.ReadFile(filepath.Join(blobDir(repoDir, digest), "manifest.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func filePullDir(ref, dst string) (string, error) {
	repoDir, target, err := fileRef(ref)
	if err != nil {
		return "", err
	}
	digest, found, err := resolveTarget(repoDir, target)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("artifact: pull %s: not found", ref)
	}
	m, err := readFileManifest(repoDir, digest)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	for _, f := range m.Files {
		if err := copyFile(filepath.Join(blobDir(repoDir, digest), "files", f.Name), filepath.Join(dst, f.Name), 0o644); err != nil {
			return "", fmt.Errorf("artifact: pull %s: %w", ref, err)
		}
	}
	return digest, nil
}

// fileDelete removes a tag, and the content it pointed at when no other
// tag still does; a digest target removes the content and every tag on it.
func fileDelete(ref string) error {
	repoDir, target, err := fileRef(ref)
	if err != nil {
		return err
	}
	digest, found, err := resolveTarget(repoDir, target)
	if err != nil || !found {
		return err
	}
	if !strings.HasPrefix(target, "sha256:") {
		if err := os.Remove(tagFile(repoDir, target)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	tags, _ := os.ReadDir(filepath.Join(repoDir, "tags"))
	for _, t := range tags {
		b, err := os.ReadFile(tagFile(repoDir, t.Name()))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == digest {
			if strings.HasPrefix(target, "sha256:") {
				_ = os.Remove(tagFile(repoDir, t.Name()))
			} else {
				return nil // another tag keeps the content
			}
		}
	}
	return os.RemoveAll(blobDir(repoDir, digest))
}

// TarDir writes every regular file directly under src into the tar
// archive dst (flat, reproducible); Untar unpacks such an archive into
// dst, ignoring any path in the entries.
func TarDir(src, dst string) error { return tarDir(src, dst) }

func Untar(src, dst string) error { return untar(src, dst) }
