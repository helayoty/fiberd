// Package artifact packages a zygote as an OCI artifact and moves it
// through a registry, so every home that holds a grant for a template
// warms byte-identical zygote pages from one content-addressed source.
//
// Layout (one manifest, three layers, all titled):
//
//	zygote       the executable, application/vnd.fiberd.zygote.bin.v1
//	config.json  argv, arch, kernel and libc of the build host, digests
//	images.tar   CRIU images of the zygote taken right after READY: the
//	             parent pages that fiber deltas are computed against
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
	"runtime"
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
	Args         []string  `json:"args"`
	Arch         string    `json:"arch"`
	Kernel       string    `json:"kernel"`
	Libc         string    `json:"libc"`
	ZygoteSHA256 string    `json:"zygote_sha256"`
	HasImages    bool      `json:"has_images"`
	BuiltAt      time.Time `json:"built_at"`
	// Digest is the manifest digest. It is never stored in config.json
	// (it is a layer); Pull fills it from the transfer, and ReadDigest
	// reads the DIGEST side file Pack and Pull write.
	Digest string `json:"-"`
}

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
// returns the manifest digest. plainHTTP selects http:// registries.
func Push(ctx context.Context, dir, ref string, plainHTTP bool) (string, error) {
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

// Pull downloads the artifact at repo@digest (or repo:tag) into dst and
// unpacks images.tar. The manifest digest is verified by the transfer.
func Pull(ctx context.Context, ref, dst string, plainHTTP bool) (Config, error) {
	repo, target, err := repository(ref, plainHTTP)
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
	if cfg.HasImages {
		if err := untar(filepath.Join(dst, fileImages), ImagesDir(dst)); err != nil {
			return Config{}, err
		}
	}
	if err := writeDigest(dst, desc.Digest.String()); err != nil {
		return Config{}, err
	}
	cfg.Digest = desc.Digest.String()
	return cfg, nil
}

func repository(ref string, plainHTTP bool) (*remote.Repository, string, error) {
	name, target := ref, ""
	if i := strings.Index(ref, "@"); i >= 0 {
		name, target = ref[:i], ref[i+1:]
	} else if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		// host:port/repo has a colon before the last slash; a tag has none after.
		if strings.Contains(ref[:i], "/") {
			name, target = ref[:i], ref[i+1:]
		}
	}
	repo, err := remote.NewRepository(name)
	if err != nil {
		return nil, "", fmt.Errorf("artifact: %q: %w", ref, err)
	}
	repo.PlainHTTP = plainHTTP
	return repo, target, nil
}

// HostInfo fills the parity fields for the running host.
func HostInfo() (arch, kernel, libc string) {
	arch = runtime.GOARCH
	kernel = unameRelease()
	libc = libcVersion()
	return
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
		if e.IsDir() {
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
	if err := os.MkdirAll(dst, 0o755); err != nil {
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
		name := filepath.Base(hdr.Name) // flat archive; never trust paths
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(filepath.Join(dst, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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
