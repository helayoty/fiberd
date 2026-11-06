// Package helper starts the programs fiberd hands privileged work to,
// such as criu, runc, runsc and ldd. A helper runs from a fixed path with
// a fixed environment, so it sees only what fiberd chose. fiberd's own
// environment stays as it started, because an operator's proxy settings
// live there.
package helper

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
)

// PathEnv is the PATH of every process fiberd gives a fixed environment.
const PathEnv = "PATH=/usr/bin:/bin"

// dirs is where a bare name is looked for, in order. The images install
// criu in /usr/local/sbin and runsc in /usr/local/bin, and Debian ships
// runc in /usr/sbin and /usr/bin.
var dirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Command is exec.CommandContext for a helper, started from the path
// Resolve gives with PathEnv as its whole environment. A name Resolve
// refuses fails at the start with Resolve's error.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	path, err := Resolve(name)
	if err != nil {
		// A path with a slash, so os/exec does no search of its own. The
		// start returns Err before it reads this.
		path = "/"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{PathEnv}
	cmd.Err = err
	return cmd
}

// Resolve is the path of the helper called name. A caller needs it for a
// helper that runs through a wrapper, since PathEnv reaches only part of
// dirs. A bare name is found in dirs and never on PATH. An absolute name
// is returned as it is, and its exec says whether it exists. A relative
// path is refused, because the working directory would pick the program.
func Resolve(name string) (string, error) { return resolve(name, dirs) }

func resolve(name string, dirs []string) (string, error) {
	switch {
	case filepath.IsAbs(name):
		return name, nil
	case strings.ContainsRune(name, filepath.Separator):
		return "", fmt.Errorf("helper: %q is neither absolute nor a bare name", name)
	}
	for _, dir := range dirs {
		// The joined name holds a slash, so LookPath only checks that it
		// is an executable file.
		if path, err := exec.LookPath(filepath.Join(dir, name)); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("helper: no %q in %s: %w", name, strings.Join(dirs, ":"), fs.ErrNotExist)
}
