//go:build linux && integration

package pythontest

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// fileStore is the runtime's file store.
func fileStore(t *testing.T, rt core.Runtime) core.FileStore {
	t.Helper()
	fs, ok := rt.(core.FileStore)
	if !ok {
		t.Fatal("the runtime moves no files")
	}
	return fs
}

// upload puts body at rel in the fiber's workspace.
func upload(t *testing.T, rt core.Runtime, fiberID, rel, body string) {
	t.Helper()
	if _, err := fileStore(t, rt).Upload(context.Background(), fiberID, rel, int64(len(body)), 0o644, nil, strings.NewReader(body)); err != nil {
		t.Fatalf("upload %s: %v", rel, err)
	}
}

// download reads rel from the fiber's workspace.
func download(t *testing.T, rt core.Runtime, fiberID, rel string) string {
	t.Helper()
	f, err := fileStore(t, rt).Download(context.Background(), fiberID, rel, 0)
	if err != nil {
		t.Fatalf("download %s: %v", rel, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// foreignEntry is one file of fiberd-foreign.json, the fields read here.
type foreignEntry struct {
	Key   string `json:"key"`
	Path  string `json:"path"`
	Mount string `json:"mount"`
}

// minForeign is the fewest files a Python fiber must hold through the
// container's mounts at its park. The interpreter, the loader, libc,
// the SDK's extension and the stdlib modules it loads are each one. A
// static template such as refzygote holds its own text and little else.
const minForeign = 6

// TestWorkspaceManyForeignFiles parks a runc fiber of the Python
// reference template that has a workspace. It was born into its own
// copy of the container's mount namespace, so every file it loaded
// before the birth sits on a container mount, dozens for a dynamic
// template, and the dump must name each to criu. The park records them
// in fiberd-foreign.json, and the resume reopens each on the home and
// hands it back, so the fiber serves on with its workspace.
func TestWorkspaceManyForeignFiles(t *testing.T) {
	var rc *backend
	for i := range backends {
		if backends[i].name == "runc" {
			rc = &backends[i]
		}
	}
	if rc == nil {
		t.Skip("no runc here")
	}
	ctx := context.Background()
	cases := []struct {
		name string
		sync bool
	}{
		{name: "async park"},
		{name: "sync park", sync: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := rc.open(t, rc.template)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("no park and resume here")
			}
			g := core.Grant{UID: "gpyws", TemplateDigest: "sha256:pyref", FiberMax: 4, WBudgetBytes: 64 << 20, DiskBudgetBytes: 1 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			upload(t, rt, h.ID, "in/data.txt", "from the host\n")
			if got := talk(t, h.Endpoint, "read /workspace/in/data.txt"); got != "from the host" {
				t.Fatalf("the fiber read %q, want the uploaded file's first line", got)
			}
			if got := talk(t, h.Endpoint, "incr"); got != "1" {
				t.Fatalf("incr = %q", got)
			}
			ref, err := rt.Park(ctx, h.ID, tc.sync)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(ref, "fiberd-foreign.json"))
			if err != nil {
				t.Fatalf("the park recorded no foreign files: %v", err)
			}
			var list []foreignEntry
			if err := json.Unmarshal(b, &list); err != nil {
				t.Fatalf("fiberd-foreign.json: %v", err)
			}
			python := false
			var paths []string
			for _, e := range list {
				paths = append(paths, e.Path)
				if strings.Contains(e.Path, "python") {
					python = true
				}
			}
			t.Logf("%d foreign files: %s", len(list), strings.Join(paths, " "))
			if len(list) < minForeign || !python {
				t.Fatalf("fiberd-foreign.json holds %d files, want at least %d with the interpreter's among them", len(list), minForeign)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 30 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
			for _, ask := range []struct{ line, want string }{
				{line: "incr", want: "2"},
				{line: "read /workspace/in/data.txt", want: "from the host"},
				{line: "fence", want: h2.ID},
			} {
				if got := talk(t, h2.Endpoint, ask.line); got != ask.want {
					t.Errorf("%s after the resume = %q, want %q", ask.line, got, ask.want)
				}
			}
			if got := download(t, rt, h2.ID, "in/data.txt"); got != "from the host\n" {
				t.Errorf("download after the resume = %q", got)
			}
		})
	}
}
