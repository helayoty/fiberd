package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// TemplateMount is where a backend that runs templates inside a root
// filesystem of its own (gvisor, runc) binds a registry template's
// executable, read-only. The path is the same on every home, so a park
// taken on one home restores on another whose state and cache live
// elsewhere. The command then runs as TemplateMount/<executable>.
const TemplateMount = "/fiberd/template"

// TemplateMountOptions bind the template read-only, with no setuid and no
// device nodes honoured, in OCI spelling. runsc compares them exactly at
// restore, so a change here parts old parks from new homes.
var TemplateMountOptions = []string{"bind", "ro", "nosuid", "nodev"}

// StageTemplate copies a registry template's executable alone into dir,
// the directory a backend binds at TemplateMount, and returns the argv
// the sandbox runs, with its first word pointing inside the mount. The
// copy is hashed against what the host verified (Template.ZygoteSHA256)
// before anything binds it, and nothing writes dir afterwards, so a
// re-pull or a rewrite of the host's template cache while sandboxes run
// cannot reach them. Only the executable is copied, never the artifact's
// config, images or digest, and never another template. The executable
// must be a file directly in the artifact directory. On any error dir is
// removed.
func StageTemplate(t Template, dir string) ([]string, error) {
	if len(t.Argv) == 0 {
		return nil, errors.New("empty template command")
	}
	if len(t.ZygoteSHA256) != 64 {
		return nil, fmt.Errorf("template %s comes without a verified executable hash", t.Digest)
	}
	name, err := filepath.Rel(t.Dir, t.Argv[0])
	if err != nil || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("template executable %s is not a file directly in the artifact directory %s", t.Argv[0], t.Dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, name)
	sum, err := copyExecutable(t.Argv[0], dst)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("stage template: %w", err)
	}
	if sum != t.ZygoteSHA256 {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("template %s: staged executable hashes to %s, the host verified %s; the cache changed under it", t.Digest, sum[:12], t.ZygoteSHA256[:12])
	}
	return append([]string{path.Join(TemplateMount, name)}, t.Argv[1:]...), nil
}

// copyExecutable writes a read-only, executable copy of src at dst and
// returns the hex SHA-256 of the bytes it wrote, so what is hashed is
// what was copied, not what the source holds afterwards.
func copyExecutable(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o555)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		_ = out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	// The mode is applied at creation only for a new file.
	if err := os.Chmod(dst, 0o555); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
