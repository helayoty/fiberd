package fiberd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PrivateDir is where fiberd keeps what no fiber may read, such as its
// keys, ledger snapshot, deny-list, epoch, audit spool and admin socket.
// It is <state>/private, mode 0700, hidden from every fiber with its own
// mount namespace. Fibers run as fiberd's uid, so file modes alone
// would not stop them. Templates and deltas stay directly under -state,
// where fibers and CRIU need them.
func (c *Config) PrivateDir() string { return filepath.Join(c.StateDir, "private") }

// ensurePrivate creates PrivateDir, or checks the one that is there.
// -state is visible to fibers, so what sits at this name is checked
// before anything is written through it. A symlink a fiber planted there
// would send the keys wherever it points, and MkdirAll and Chmod both
// follow one.
func (c *Config) ensurePrivate() error { return ensurePrivate(c.StateDir, c.PrivateDir(), os.Chmod) }

// chmod tightens the private directory's mode. It is a parameter so a
// test can stand in for a file system that refuses, which only a mount
// does.
func ensurePrivate(stateDir, privateDir string, chmod func(string, os.FileMode) error) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if err := os.Mkdir(privateDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("private state dir: %w", err)
	}
	fi, err := os.Lstat(privateDir)
	switch {
	case err != nil:
		return fmt.Errorf("private state dir: %w", err)
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("private state dir %s is a symlink, refusing to use it", privateDir)
	case !fi.IsDir():
		return fmt.Errorf("private state dir %s is not a directory", privateDir)
	}
	// An existing directory keeps the mode it was made with. This one
	// must be fiberd's alone.
	if err := chmod(privateDir, 0o700); err != nil {
		return fmt.Errorf("private state dir: %w", err)
	}
	return nil
}
