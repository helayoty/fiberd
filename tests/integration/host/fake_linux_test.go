//go:build linux && integration

package hosttest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// fake is a backend that forks nothing. The kernel behaviour under test
// is the host's cgroup tree, so the fake only answers the runtime and
// reports the exits a test asks for. The tasks in the leaves are the
// tests' own (startSleeper).
type fake struct {
	tier  core.Tier
	exits chan backend.Exit
	// footprint is what Clone reports as the leaf's own count before
	// the hand-out.
	footprint uint64
	// warm is what Warm answers, with the id and pid filled in.
	warm backend.Warm

	mu     sync.Mutex
	fibers map[string]bool // alive by fence
	clones int
	closed bool
}

func newFake(tier core.Tier) *fake {
	return &fake{tier: tier, exits: make(chan backend.Exit, 16), fibers: map[string]bool{}}
}

func (b *fake) Name() string    { return "fake" }
func (b *fake) Tier() core.Tier { return b.tier }

func (b *fake) Warm(_ context.Context, spec backend.WarmSpec) (backend.Warm, error) {
	w := b.warm
	w.ID, w.PID = spec.GrantUID, 1
	return w, nil
}

func (b *fake) Unwarm(string) {}

func (b *fake) Clone(_ context.Context, _ string, spec backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clones++
	b.fibers[spec.Fence] = true
	return backend.Fiber{ID: spec.Fence, PID: 2, Footprint: b.footprint}, nil
}

// cloned is how many fibers the runtime asked for.
func (b *fake) cloned() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clones
}

func (b *fake) Park(_ context.Context, fiberID string, spec backend.ParkSpec) error {
	if err := os.MkdirAll(spec.Dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(spec.Dir, "pages-1.img"), []byte("dirty pages of "+fiberID), 0o644); err != nil {
		return err
	}
	if !spec.Sync {
		b.die(fiberID, "exit:0")
	}
	return nil
}

func (b *fake) Resume(context.Context, backend.ResumeSpec) (backend.Fiber, error) {
	return backend.Fiber{}, errors.New("fake: no resume")
}

func (b *fake) Kill(fiberID string) error {
	b.die(fiberID, "signal:SIGKILL")
	return nil
}

// die reports a fiber's end once, with the given status.
func (b *fake) die(fiberID, status string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.fibers[fiberID] || b.closed {
		return
	}
	b.fibers[fiberID] = false
	b.exits <- backend.Exit{FiberID: fiberID, Status: status}
}

func (b *fake) Exits() <-chan backend.Exit { return b.exits }

func (b *fake) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.exits)
	}
}

// mapped is a backend that maps each grant's root to one uid, as runc
// does, so the runtime hands the grant its cgroup.procs.
type mapped struct {
	*fake
	uid uint32
	err error
}

func (m *mapped) MappedRoot(string) (uint32, error) { return m.uid, m.err }

// sandbox is a backend whose fibers are sandboxes, as gVisor's are. It
// carries a fixed footprint the runtime subtracts from the leaf's count,
// and its tenants are isolated by the sandbox rather than by task limits.
type sandbox struct{ *fake }

func (sandbox) FiberOverheadBytes() uint64 { return 0 }
func (sandbox) IsolatesTenants() bool      { return true }

// checkpointing is a fork backend with a delta codec and a self
// checkpoint, as proc is. A parent is a directory with a "pages" file,
// hashed by content. A delta is a "delta.json" naming its parent.
type checkpointing struct{ *fake }

type fakeParent struct{ sha string }

func (p fakeParent) SHA256() string { return p.sha }
func (fakeParent) Close()           {}

type fakeDelta struct {
	Parent string `json:"parent"`
	Bytes  uint64 `json:"bytes"`
}

func (checkpointing) CheckpointWarm(_ context.Context, warmID, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "pages"), []byte("zygote pages of "+warmID), 0o644)
}

func (checkpointing) ImageBytes(string) (uint64, error) { return 0, nil }

func (checkpointing) LoadParent(dir string) (backend.Parent, error) {
	b, err := os.ReadFile(filepath.Join(dir, "pages"))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return fakeParent{hex.EncodeToString(sum[:])}, nil
}

func (checkpointing) Compute(dir string, parent backend.Parent) (backend.DeltaInfo, error) {
	d := fakeDelta{Parent: parent.SHA256(), Bytes: 7}
	b, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(dir, "delta.json"), b, 0o644); err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: d.Parent, Bytes: d.Bytes}, nil
}

func (checkpointing) HasDelta(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "delta.json"))
	return err == nil
}

func (checkpointing) ReadDeltaInfo(dir string) (backend.DeltaInfo, error) {
	b, err := os.ReadFile(filepath.Join(dir, "delta.json"))
	if err != nil {
		return backend.DeltaInfo{}, err
	}
	var d fakeDelta
	if err := json.Unmarshal(b, &d); err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: d.Parent, Bytes: d.Bytes}, nil
}

func (checkpointing) Merge(string, backend.Parent) error { return nil }

// The compositions offer the interfaces the tests rely on.
var (
	_ backend.Backend          = (*fake)(nil)
	_ backend.IDMapper         = (*mapped)(nil)
	_ backend.Overheader       = sandbox{}
	_ backend.Isolator         = sandbox{}
	_ backend.DeltaCodec       = checkpointing{}
	_ backend.SelfCheckpointer = checkpointing{}
)

// shaOf is the hash of a fake parent holding pages.
func shaOf(pages string) string {
	sum := sha256.Sum256([]byte(pages))
	return hex.EncodeToString(sum[:])
}
