package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// BuildOptions describe how to turn a zygote executable into an artifact.
type BuildOptions struct {
	Zygote string   // path to the executable
	Args   []string // arguments the home will pass
	Out    string   // artifact directory to create
	// SkipImages builds an artifact without a CRIU checkpoint (no criu on
	// this host, or a template that does not need deltas). The zygote is
	// still run to READY once, as a smoke test, unless NoSmoke.
	SkipImages bool
	// NoSmoke skips that run, for a template whose warm-up is slow or one
	// this host cannot run, such as a gVisor-mode template that waits on
	// /proc/gvisor/checkpoint, another architecture's, or any off Linux.
	NoSmoke bool
	// SealTo is the fleet's public wrap key (fleet-pub.json, which
	// grant-issuer keygen -alg A256GCM writes). images.tar is sealed to
	// it, and a build with images refuses to run without it, so no
	// template memory is ever packed in the clear. A build with
	// SkipImages needs none.
	SealTo       *WrapPublicKey
	CRIU         criu.Options
	ReadyTimeout time.Duration
	// Platform is the build host the artifact records. Empty fields are
	// detected (ldd for the libc on Linux), so a caller that names all
	// three runs nothing. Backend and Templates are not recorded.
	Platform Platform
}

// Build runs the zygote the way a home does (control channel on fd 3),
// waits for READY, checkpoints it with criu --leave-running, seals the
// images to SealTo, and writes the artifact directory. Returns the packed
// manifest digest. The plaintext images and their tar are removed once
// sealed. With SkipImages it only checks that the zygote reaches READY,
// which needs no criu, and with NoSmoke as well it runs nothing.
//
//	SkipImages  NoSmoke   runs the zygote   criu   images.tar
//	false       any       yes               yes    yes, sealed to SealTo
//	true        false     yes, to READY     no     no
//	true        true      no                no     no
func Build(ctx context.Context, o BuildOptions) (string, error) {
	if o.Zygote == "" || o.Out == "" {
		return "", errors.New("artifact: Zygote and Out are required")
	}
	if !o.SkipImages && o.SealTo == nil {
		return "", errors.New("artifact: images are sealed to the fleet's wrap key; pass -seal-to fleet-pub.json (grant-issuer keygen -alg A256GCM writes it), or -skip-images")
	}
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = 30 * time.Second
	}
	var err error
	if o.Out, err = filepath.Abs(o.Out); err != nil {
		return "", err
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return "", err
	}
	if err := copyFile(o.Zygote, ZygotePath(o.Out), 0o755); err != nil {
		return "", err
	}
	sum, err := fileSHA256(ZygotePath(o.Out))
	if err != nil {
		return "", err
	}
	p := o.Platform.Complete()
	cfg := Config{Args: o.Args, Arch: p.Arch, Kernel: p.Kernel, Libc: p.Libc, ZygoteSHA256: sum,
		Linking: Linking(ZygotePath(o.Out)), BuiltAt: time.Now().UTC().Truncate(time.Second)}

	// What an earlier build into Out left is not this build's.
	_ = os.RemoveAll(filepath.Join(o.Out, dirImages))
	_ = os.Remove(filepath.Join(o.Out, fileImages))
	switch {
	case !o.SkipImages:
		s, err := sealedImages(ctx, o)
		if err != nil {
			return "", err
		}
		cfg.Images = &s
	case !o.NoSmoke:
		if err := smokeZygote(ctx, o); err != nil {
			return "", fmt.Errorf("%w (a smoke test, skipped with -no-smoke)", err)
		}
	}
	if err := writeConfig(o.Out, cfg); err != nil {
		return "", err
	}
	return Pack(ctx, o.Out)
}

// sealedImages checkpoints the zygote into Out/images, tars the images
// beside them and seals the tar into Out/images.tar for o.SealTo. The
// plaintext directory and tar are gone when it returns, whatever happens.
func sealedImages(ctx context.Context, o BuildOptions) (ImagesSeal, error) {
	imagesDir := filepath.Join(o.Out, dirImages)
	plain := filepath.Join(o.Out, fileImages+".plain")
	defer func() {
		_ = os.RemoveAll(imagesDir)
		_ = os.Remove(plain)
	}()
	if err := checkpointZygote(ctx, o, imagesDir); err != nil {
		return ImagesSeal{}, err
	}
	if err := tarDir(imagesDir, plain); err != nil {
		return ImagesSeal{}, err
	}
	return SealImages(plain, filepath.Join(o.Out, fileImages), o.SealTo)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
