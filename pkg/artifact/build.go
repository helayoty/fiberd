package artifact

import (
	"context"
	"errors"
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
	// this host, or a template that does not need deltas).
	SkipImages   bool
	CRIU         criu.Options
	ReadyTimeout time.Duration
}

// Build runs the zygote the way a home does (control channel on fd 3),
// waits for READY, checkpoints it with criu --leave-running, and writes
// the artifact directory. Returns the packed manifest digest.
func Build(ctx context.Context, o BuildOptions) (string, error) {
	if o.Zygote == "" || o.Out == "" {
		return "", errors.New("artifact: Zygote and Out are required")
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
	arch, kernel, libc := HostInfo()
	cfg := Config{Args: o.Args, Arch: arch, Kernel: kernel, Libc: libc, ZygoteSHA256: sum,
		BuiltAt: time.Now().UTC().Truncate(time.Second)}

	if !o.SkipImages {
		if err := checkpointZygote(ctx, o, filepath.Join(o.Out, dirImages)); err != nil {
			return "", err
		}
		if err := tarDir(filepath.Join(o.Out, dirImages), filepath.Join(o.Out, fileImages)); err != nil {
			return "", err
		}
		cfg.HasImages = true
	}
	if err := writeConfig(o.Out, cfg); err != nil {
		return "", err
	}
	return Pack(ctx, o.Out)
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
