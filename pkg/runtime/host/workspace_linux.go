//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host/wsfs"
)

// workspaceTar is the file a park writes the workspace to, beside the
// images in the delta directory. It rides seal, signature, quota,
// publish, claim, export and import with the rest of the directory.
const workspaceTar = "workspace.tar"

// workspace is one fiber's workspace on this home: a directory under
// WorkspaceDir that wsfs owns, with the fiber's tree at root/ and
// fiberd's staging beside it. The backend mounts root/ at
// backend.WorkspaceMount in the fiber.
type workspace struct {
	dir    string
	ws     *wsfs.Workspace
	budget *wsfs.Counter
}

// workspaceDir is where fence's workspace lives.
func (r *Runtime) workspaceDir(fence core.Fence) string {
	return filepath.Join(r.cfg.WorkspaceDir, fence.GrantUID, fmt.Sprintf("%d-%d", fence.Epoch, fence.Seq))
}

// newWorkspace makes an empty workspace for fence under g's disk
// budget. The budget counts what fiberd writes into it, in memory, until
// a kernel quota takes over (#33, stage 7). The tree the fiber writes is
// bounded at park by the same limits.
func (r *Runtime) newWorkspace(fence core.Fence, g core.Grant) (*workspace, error) {
	if g.DiskBudgetBytes > uint64(1<<62) {
		return nil, fmt.Errorf("host: grant %s: disk budget %d is past what a workspace can count", g.UID, g.DiskBudgetBytes)
	}
	dir := r.workspaceDir(fence)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(dir)
	owner, err := r.workspaceOwner(g.UID)
	if err != nil {
		return nil, err
	}
	limits := wsfs.Limits{Bytes: int64(g.DiskBudgetBytes)}
	budget := wsfs.NewCounter(limits)
	ws, err := wsfs.Open(dir, wsfs.Options{Budget: budget, Limits: limits, Owner: owner})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("host: workspace of %s: %w", fence, err)
	}
	if owner != nil {
		if err := searchableBy(owner, filepath.Dir(dir), dir); err != nil {
			ws.Close()
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("host: workspace of %s: %w", fence, err)
		}
	}
	return &workspace{dir: dir, ws: ws, budget: budget}, nil
}

// workspaceOwner is who owns a workspace of grantUID and everything
// fiberd writes into it. A backend that maps the grant's root into a
// user namespace (runc) gets that root, so the fiber, uid 0 inside,
// owns its tree and can write what it was given. Host root's files
// would read as nobody there. Any other backend's fiber runs as
// fiberd's uid, and nil keeps fiberd's ids.
func (r *Runtime) workspaceOwner(grantUID string) (*wsfs.Owner, error) {
	m, ok := r.be.(backend.IDMapper)
	if !ok {
		return nil, nil
	}
	uid, err := m.MappedRoot(grantUID)
	if err != nil {
		return nil, fmt.Errorf("host: workspace owner of grant %s: %w", grantUID, err)
	}
	return &wsfs.Owner{UID: int(uid), GID: int(uid)}, nil
}

// searchableBy lets the owner of a workspace, the grant's mapped root,
// search down to its tree, the way the run directory is shared with it.
// criu restores a runc fiber's workspace bind from inside the restored
// user namespace, as that root, and opens the tree by its path. Each
// level stays fiberd's, with the owner's group and search alone (0710),
// so no other grant and no other user gets in, nothing can be listed,
// and the staging directory beside the tree stays fiberd's alone.
// WorkspaceDir itself lets anyone search it (workspaceDirMode).
func searchableBy(owner *wsfs.Owner, dirs ...string) error {
	for _, d := range dirs {
		if err := os.Chown(d, -1, owner.GID); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o710); err != nil {
			return err
		}
	}
	return nil
}

// workspaceDirMode is WorkspaceDir's mode, fiberd's alone (0700), or
// searchable by anyone and listed by nobody (0711) when the backend maps
// each grant's root into a user namespace, whose root must walk to its
// tree (searchableBy). The levels below are gated by each grant's group.
func workspaceDirMode(be backend.Backend) os.FileMode {
	if _, ok := be.(backend.IDMapper); ok {
		return 0o711
	}
	return 0o700
}

// unpackWorkspace fills a fresh workspace for fence from the park
// archive in dir, for the resume of that park. A delta without an
// archive gives a fiber of a grant without a disk budget no workspace,
// and nil. The two mixed are refused, since the restored fiber's tree
// would not match its images.
func (r *Runtime) unpackWorkspace(dir string, fence core.Fence, g core.Grant) (*workspace, error) {
	f, err := os.Open(filepath.Join(dir, workspaceTar))
	switch {
	case errors.Is(err, fs.ErrNotExist) && g.DiskBudgetBytes == 0:
		return nil, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("host: delta %s has no %s, but grant %s has a disk budget", dir, workspaceTar, g.UID)
	case err != nil:
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if g.DiskBudgetBytes == 0 {
		return nil, fmt.Errorf("host: delta %s carries a workspace, but grant %s has no disk budget", dir, g.UID)
	}
	ws, err := r.newWorkspace(fence, g)
	if err != nil {
		return nil, err
	}
	if err := ws.ws.Unpack(f); err != nil {
		ws.remove()
		return nil, fmt.Errorf("host: delta %s: unpack %s: %w", dir, workspaceTar, err)
	}
	return ws, nil
}

// root is the directory the fiber's tree lives in, "" for no workspace.
func (w *workspace) root() string {
	if w == nil {
		return ""
	}
	return filepath.Join(w.dir, "root")
}

// size is the tree's apparent bytes and entries.
func (w *workspace) size() (bytes, entries uint64, err error) {
	b, e, err := w.ws.Size()
	if err != nil {
		return 0, 0, err
	}
	return uint64(b), uint64(e), nil
}

// capture writes the tree as workspaceTar into dir, fiberd's alone,
// durable before it returns. A failed capture leaves nothing behind.
func (w *workspace) capture(dir string) (err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, workspaceTar)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(p)
		}
	}()
	if err := w.ws.Capture(f); err != nil {
		return fmt.Errorf("capture the workspace: %w", err)
	}
	return f.Sync()
}

// remove closes the workspace and takes its directory away. Nil is
// nothing to remove.
func (w *workspace) remove() {
	if w == nil {
		return
	}
	w.ws.Close()
	_ = os.RemoveAll(w.dir)
}

// workspaceOf finds a live fiber's workspace. An unknown fiber is
// ErrFiberUnknown and one without a workspace ErrNoWorkspace.
func (r *Runtime) workspaceOf(fiberID string) (*workspace, error) {
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	var ws *workspace
	if ok {
		ws = f.ws
	}
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", core.ErrFiberUnknown, fiberID)
	}
	if ws == nil {
		return nil, fmt.Errorf("%w: fiber %s", core.ErrNoWorkspace, fiberID)
	}
	return ws, nil
}

// Upload implements core.FileStore.
func (r *Runtime) Upload(_ context.Context, fiberID, path string, size int64, mode fs.FileMode, sum []byte, rd io.Reader) (core.FileInfo, error) {
	ws, err := r.workspaceOf(fiberID)
	if err != nil {
		return core.FileInfo{}, err
	}
	info, err := ws.ws.Upload(path, size, mode, sum, rd)
	if err != nil {
		return core.FileInfo{}, err
	}
	return fileInfo(info), nil
}

// Download implements core.FileStore.
func (r *Runtime) Download(_ context.Context, fiberID, path string, offset int64) (core.FileReader, error) {
	ws, err := r.workspaceOf(fiberID)
	if err != nil {
		return nil, err
	}
	f, err := ws.ws.Download(path, offset)
	if err != nil {
		return nil, err
	}
	return fileReader{f}, nil
}

// ListFiles implements core.FileStore.
func (r *Runtime) ListFiles(_ context.Context, fiberID, dir string) ([]core.FileInfo, error) {
	ws, err := r.workspaceOf(fiberID)
	if err != nil {
		return nil, err
	}
	infos, err := ws.ws.List(dir)
	if err != nil {
		return nil, err
	}
	out := make([]core.FileInfo, len(infos))
	for i, info := range infos {
		out[i] = fileInfo(info)
	}
	return out, nil
}

// fileReader is a wsfs.File as a core.FileReader.
type fileReader struct{ *wsfs.File }

func (f fileReader) Info() core.FileInfo { return fileInfo(f.File.Info()) }

func fileInfo(i wsfs.Info) core.FileInfo {
	return core.FileInfo{Path: i.Path, Size: i.Size, Mode: i.Mode, ModTime: i.ModTime, SHA256: i.SHA256}
}

var (
	_ core.FileStore          = (*Runtime)(nil)
	_ backend.WorkspaceHolder = (*Runtime)(nil)
)
