// Package artifact packages a zygote as an OCI artifact and moves it
// through a registry, so every home that holds a grant for a template
// warms byte-identical zygote pages from one content-addressed source.
//
// Layout (one manifest, three layers, all titled):
//
//	zygote       the executable, application/vnd.fiberd.zygote.bin.v1
//	config.json  argv, arch, kernel and libc of the build host, digests,
//	             and how images.tar is sealed
//	images.tar   CRIU images of the zygote taken right after READY: the
//	             parent pages that fiber deltas are computed against.
//	             Sealed to the fleet's wrap key (wrap.go), never plain
//
// The manifest digest is the template digest a grant carries.
package artifact

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	ArtifactType    = "application/vnd.fiberd.zygote.v1"
	MediaTypeBinary = "application/vnd.fiberd.zygote.bin.v1"
	MediaTypeConfig = "application/vnd.fiberd.zygote.config.v1+json"
	MediaTypeImages = "application/vnd.fiberd.zygote.criu.v1.tar"

	fileZygote   = "zygote"
	fileConfig   = "config.json"
	fileImages   = "images.tar"
	fileManifest = "manifest.json"
	dirImages    = "images"
)

// Config describes the zygote and the host it was checkpointed on. The
// parity fields gate cross-host resume: a delta over these pages only
// restores where the kernel and libc match.
type Config struct {
	Args         []string `json:"args"`
	Arch         string   `json:"arch"`
	Kernel       string   `json:"kernel"`
	Libc         string   `json:"libc"`
	ZygoteSHA256 string   `json:"zygote_sha256"`
	// Linking is LinkStatic or LinkDynamic (linking.go). A home whose
	// backend runs the template inside a root filesystem of its own
	// refuses a dynamic one, since it cannot tell whether that
	// filesystem holds the libc. Empty in a config written before the
	// fact was recorded, which counts as dynamic.
	Linking string `json:"linking,omitempty"`
	// Images says how images.tar is sealed. Nil when the artifact has no
	// images. An artifact never carries images in the clear.
	Images  *ImagesSeal `json:"images,omitempty"`
	BuiltAt time.Time   `json:"built_at"`
	// Digest is the manifest digest. It is never stored in config.json
	// (it is a layer); Pull fills it from the transfer, and ReadDigest
	// reads the DIGEST side file Pack and Pull write.
	Digest string `json:"-"`
}

// HasImages reports whether the artifact carries a sealed images.tar.
func (c Config) HasImages() bool { return c.Images != nil }

// ReadConfig loads config.json from an artifact directory.
func ReadConfig(dir string) (Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileConfig))
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("artifact: %s: %w", fileConfig, err)
	}
	return c, nil
}

func writeConfig(dir string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, fileConfig), b, 0o644)
}

// ZygotePath is where the executable lives in an artifact directory.
func ZygotePath(dir string) string { return filepath.Join(dir, fileZygote) }

// ImagesDir is where images.tar is unpacked in a pulled artifact.
func ImagesDir(dir string) string { return filepath.Join(dir, dirImages) }

// Pack computes the manifest for an artifact directory and records its
// digest in the DIGEST side file (never inside a layer, or the digest
// would change itself). It is deterministic for a given directory: the
// created annotation is the build time from the config, not now.
func Pack(ctx context.Context, dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	cfg, err := ReadConfig(dir)
	if err != nil {
		return "", err
	}
	fs, err := file.New(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = fs.Close() }()
	desc, err := pack(ctx, fs, dir, cfg)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), writeDigest(dir, desc.Digest.String())
}

func writeDigest(dir, d string) error {
	return os.WriteFile(filepath.Join(dir, "DIGEST"), []byte(d+"\n"), 0o644)
}

// ReadDigest returns the digest Pack recorded.
func ReadDigest(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "DIGEST"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func pack(ctx context.Context, fs *file.Store, dir string, cfg Config) (ocispec.Descriptor, error) {
	var layers []ocispec.Descriptor
	add := func(name, mt string, required bool) error {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			if required {
				return fmt.Errorf("artifact: missing %s: %w", name, err)
			}
			return nil
		}
		// The store resolves the path against its own directory.
		d, err := fs.Add(ctx, name, mt, name)
		if err != nil {
			return err
		}
		layers = append(layers, d)
		return nil
	}
	if err := add(fileZygote, MediaTypeBinary, true); err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := add(fileConfig, MediaTypeConfig, true); err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := checkImagesLayer(dir, cfg); err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := add(fileImages, MediaTypeImages, false); err != nil {
		return ocispec.Descriptor{}, err
	}
	created := cfg.BuiltAt.UTC().Format(time.RFC3339)
	return oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
		Layers:              layers,
		ManifestAnnotations: map[string]string{ocispec.AnnotationCreated: created, "io.fiberd.arch": cfg.Arch},
	})
}

// Push uploads the artifact directory to ref ("host/repo:tag") and
// returns the manifest digest.
func Push(ctx context.Context, dir, ref string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	cfg, err := ReadConfig(dir)
	if err != nil {
		return "", err
	}
	fs, err := file.New(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = fs.Close() }()
	desc, err := pack(ctx, fs, dir, cfg)
	if err != nil {
		return "", err
	}
	repo, tag, err := repository(ref)
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

// Pull downloads the artifact at repo@digest (or repo:tag) into dst. The
// manifest digest is verified by the transfer. Sealed images stay sealed.
// A home opens them with UnpackImages.
func Pull(ctx context.Context, ref, dst string) (Config, error) {
	repo, target, err := repository(ref)
	if err != nil {
		return Config{}, err
	}
	if target == "" {
		return Config{}, errors.New("artifact: pull needs repo@digest or repo:tag")
	}
	dst, err = filepath.Abs(dst)
	if err != nil {
		return Config{}, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return Config{}, err
	}
	fs, err := file.New(dst)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = fs.Close() }()
	desc, err := oras.Copy(ctx, repo, target, fs, target, oras.DefaultCopyOptions)
	if err != nil {
		return Config{}, fmt.Errorf("artifact: pull %s: %w", ref, err)
	}
	mb, err := content.FetchAll(ctx, fs, desc)
	if err != nil {
		return Config{}, err
	}
	if err := os.WriteFile(filepath.Join(dst, fileManifest), mb, 0o644); err != nil {
		return Config{}, err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return Config{}, err
	}
	if m.ArtifactType != ArtifactType {
		return Config{}, fmt.Errorf("artifact: %s is %q, not a zygote artifact", ref, m.ArtifactType)
	}
	if err := os.Chmod(ZygotePath(dst), 0o755); err != nil {
		return Config{}, err
	}
	cfg, err := ReadConfig(dst)
	if err != nil {
		return Config{}, err
	}
	sum, err := fileSHA256(ZygotePath(dst))
	if err != nil {
		return Config{}, fmt.Errorf("artifact: hash pulled zygote: %w", err)
	}
	if sum != cfg.ZygoteSHA256 {
		return Config{}, fmt.Errorf("artifact: pulled zygote sha256 %s does not match config %s", sum, cfg.ZygoteSHA256)
	}
	if err := checkImagesLayer(dst, cfg); err != nil {
		return Config{}, err
	}
	if err := writeDigest(dst, desc.Digest.String()); err != nil {
		return Config{}, err
	}
	cfg.Digest = desc.Digest.String()
	return cfg, nil
}

// Reverify re-checks a template cache entry a previous Pull left. The
// directory must still pack to digest and its zygote still hash to its
// config. A home then unpacks the verified images.tar afresh with
// UnpackImages. Without this, anything that can write the cache could
// change what every later warm runs.
func Reverify(ctx context.Context, dir, digest string) (Config, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Config{}, err
	}
	cfg, err := ReadConfig(dir)
	if err != nil {
		return Config{}, err
	}
	fs, err := file.New(dir)
	if err != nil {
		return Config{}, err
	}
	desc, err := pack(ctx, fs, dir, cfg)
	_ = fs.Close()
	if err != nil {
		return Config{}, err
	}
	if got := desc.Digest.String(); got != digest {
		return Config{}, fmt.Errorf("artifact: cached %s packs to %s", digest, got)
	}
	sum, err := fileSHA256(ZygotePath(dir))
	if err != nil {
		return Config{}, err
	}
	if sum != cfg.ZygoteSHA256 {
		return Config{}, fmt.Errorf("artifact: cached zygote sha256 %s does not match config %s", sum, cfg.ZygoteSHA256)
	}
	if err := os.Chmod(ZygotePath(dir), 0o755); err != nil {
		return Config{}, err
	}
	cfg.Digest = digest
	return cfg, nil
}

// checkImagesLayer refuses an artifact directory whose images.tar and
// config disagree. images.tar is there exactly when config.json says how
// it is sealed, and it must be sealed. So no template memory is packed,
// pushed or pulled in the clear.
func checkImagesLayer(dir string, cfg Config) error {
	f, err := os.Open(filepath.Join(dir, fileImages))
	switch {
	case errors.Is(err, os.ErrNotExist) && cfg.Images == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("artifact: config names sealed images but there is no %s", fileImages)
	case err != nil:
		return err
	}
	defer func() { _ = f.Close() }()
	if cfg.Images == nil {
		return fmt.Errorf("artifact: %s without a seal in config.json; images are only packed sealed (zygotectl build -seal-to)", fileImages)
	}
	magic := make([]byte, len(sealMagic))
	if _, err := io.ReadFull(f, magic); err != nil || string(magic) != sealMagic {
		return fmt.Errorf("artifact: %s is not sealed", fileImages)
	}
	return nil
}

// UnpackImages opens the sealed images.tar of the verified artifact in
// dir with the fleet key derived from k, checks it hashes to what cfg
// names, and unpacks it into ImagesDir(dir), owner-only. The unpack goes
// beside and is swapped in, so a parent already mapped from the old files
// keeps them until it is closed. Without k it says the home needs the
// fleet's seal key.
func UnpackImages(dir string, cfg Config, k *SealKey) error {
	if cfg.Images == nil {
		return errors.New("artifact: no images to unpack")
	}
	if k == nil {
		return fmt.Errorf("artifact: images sealed to fleet key %q, and this home has no seal key (-delta-seal-key)", cfg.Images.KeyID)
	}
	open := filepath.Join(dir, fileImages+".open")
	defer func() { _ = os.Remove(open) }()
	if err := OpenImages(filepath.Join(dir, fileImages), open, k, *cfg.Images); err != nil {
		return err
	}
	fresh := ImagesDir(dir) + ".verified"
	_ = os.RemoveAll(fresh)
	if err := untar(open, fresh); err != nil {
		_ = os.RemoveAll(fresh)
		return err
	}
	old := ImagesDir(dir) + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(ImagesDir(dir), old); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll(fresh)
		return err
	}
	if err := os.Rename(fresh, ImagesDir(dir)); err != nil {
		_ = os.RemoveAll(fresh)
		return err
	}
	return os.RemoveAll(old)
}

// repository is the remote repository ref names and its tag or digest.
// A ref starting with http:// is reached over plain HTTP, and one
// starting with https:// or with no scheme over TLS.
func repository(ref string) (*remote.Repository, string, error) {
	name, plainHTTP := strings.CutPrefix(ref, "http://")
	if !plainHTTP {
		name = strings.TrimPrefix(name, "https://")
	}
	target := ""
	if i := strings.Index(name, "@"); i >= 0 {
		name, target = name[:i], name[i+1:]
	} else if i := strings.LastIndex(name, ":"); i >= 0 && !strings.Contains(name[i+1:], "/") {
		// host:port/repo has a colon before the last slash; a tag has none after.
		if strings.Contains(name[:i], "/") {
			name, target = name[:i], name[i+1:]
		}
	}
	repo, err := remote.NewRepository(name)
	if err != nil {
		return nil, "", fmt.Errorf("artifact: %q: %w", ref, err)
	}
	repo.PlainHTTP = plainHTTP
	return repo, target, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkEntryName accepts the plain file names TarDir and PushDir write,
// which untar and a pull then place under their destination. Anything
// else is ErrEntryName: an empty name, "." or "..", a directory part, a
// name that leaves the destination, one over 255 bytes, or one with a
// character outside letters, digits, ".", "_" and "-".
func checkEntryName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 || name != filepath.Base(name) || !filepath.IsLocal(name) {
		return fmt.Errorf("%w: %q", ErrEntryName, name)
	}
	for _, r := range name {
		plain := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !plain {
			return fmt.Errorf("%w: %q", ErrEntryName, name)
		}
	}
	return nil
}

func tarDir(src, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	tw := tar.NewWriter(out)
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		// Regular files only, as untar unpacks. A symlink would fail the
		// copy and a FIFO would block it.
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = e.Name()
		hdr.ModTime = time.Unix(0, 0) // reproducible
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return tw.Close()
}

func untar(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// Owner-only. What is unpacked is template memory or a delta.
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// tarDir writes plain names, so a name with a directory part or
		// one that leaves dst fails the unpack instead of being mapped.
		if err := checkEntryName(hdr.Name); err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dst, hdr.Name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		_ = out.Close()
		if err != nil {
			return err
		}
	}
}
