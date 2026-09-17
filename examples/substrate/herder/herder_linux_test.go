//go:build linux

package herder_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/helayoty/fiberd/pkg/artifact"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"

	"github.com/helayoty/fiberd/examples/substrate/herder"
	subhome "github.com/helayoty/fiberd/examples/substrate/home"
	"github.com/helayoty/fiberd/examples/substrate/ingress"
	ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"
)

// The whole worker, in process, driven the way atelet drives it: an
// agent over the fork backend with a file delta registry, the substrate
// home minting grants and serving its keys, the ingress in front, and
// fake atelet directories under a temp root. Needs the dev container
// (a writable cgroup root, gcc, criu); skipped elsewhere.

func zygote(t *testing.T) (bin, cgRoot string) {
	t.Helper()
	cgRoot = os.Getenv("FIBERD_CGROUP_ROOT")
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		t.Skipf("%s not writable (run under make linux-test)", cgRoot)
	} else {
		_ = f.Close()
	}
	bin = filepath.Join(t.TempDir(), "refzygote")
	build := exec.Command("gcc", "-O2", "-pthread", "-o", bin, "../../../hack/zygote/refzygote.c", "../../../hack/zygote/libfiberzygote.c")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Skipf("cannot build refzygote: %v", err)
	}
	return bin, cgRoot
}

// worker is one Substrate worker Pod's worth of fiberd.
type worker struct {
	svc     *herder.Service
	home    *subhome.Home
	ingress *httptest.Server
	paths   herder.Paths
}

func newWorker(t *testing.T, name, bin, cgRoot, base string) *worker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The home: its own issuer on a loopback server.
	isrv := httptest.NewServer(nil)
	t.Cleanup(isrv.Close)
	h, err := subhome.New(subhome.Config{Audience: name, IssuerURL: isrv.URL, CgroupRoot: filepath.Join(cgRoot, name+fmt.Sprint(time.Now().UnixNano()%1_000_000))})
	if err != nil {
		t.Fatal(err)
	}
	isrv.Config.Handler = h.Handler()

	// The agent over the fork backend, publishing to a file registry.
	hc := host.Config{
		Backend:       procbackend.New(procbackend.Options{}),
		Templates:     map[string]string{"default": bin + " --heap-mb 8 --http"},
		CgroupRoot:    h.CgroupRoot(),
		RunDir:        filepath.Join("/tmp", "fz-"+name),
		DeltaDir:      t.TempDir(),
		TemplateCache: t.TempDir(),
		DeltaRegistry: artifact.FileScheme + filepath.Join(t.TempDir(), "registry"),
		HomeID:        name,
	}
	rt, err := host.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
		_ = os.RemoveAll(hc.RunDir)
	})
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	ag := &core.Agent{
		NodeID: name, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
		Runtime: rt, Audit: core.NopAuditor{},
		Verify: &grant.Verifier{Cache: &grant.Cache{IssuerURL: isrv.URL}, Audience: name, MaxStale: time.Hour},
		Health: h.Health(), StatusInterval: 20 * time.Millisecond,
	}
	go ag.Run(ctx)
	go fhome.Drive(ctx, h, ag) // the lane: minted grants are admitted and warmed, readiness published
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: isrv.URL, RetryAfter: time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := consumer.New(conn)

	ing, err := ingress.New(ingress.Config{})
	if err != nil {
		t.Fatal(err)
	}
	isrv2 := httptest.NewServer(ing)
	t.Cleanup(isrv2.Close)

	paths := herder.Paths{Base: base}
	svc := herder.New(herder.Config{Client: client, Grants: h, Router: ing, Paths: paths,
		Host: host.Config{DeltaRegistry: hc.DeltaRegistry, HomeID: name}})
	go svc.Run(ctx)
	return &worker{svc: svc, home: h, ingress: isrv2, paths: paths}
}

// through sends a request the way the router would: with the actor header.
func (w *worker) through(t *testing.T, method, actor, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, w.ingress.URL+path, nil)
	req.Header.Set(ingress.TargetActorHeader, actor)
	resp, err := w.ingress.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func actorReq(uid string) (*ateompb.RunWorkloadRequest, *ateompb.CheckpointWorkloadRequest, *ateompb.RestoreWorkloadRequest, *ateompb.TerminateWorkloadRequest) {
	spec := &ateompb.WorkloadSpec{Containers: []*ateompb.Container{{Name: "counter", Readyz: &ateompb.Readyz{HttpGet: &ateompb.HTTPGetAction{Path: "/readyz", Port: 80}}}}}
	id := func() (string, string, string, string, string) {
		return "ate-demo", "counter-" + uid, uid, "ate-demo", "counter"
	}
	as, an, au, ta, tn := id()
	return &ateompb.RunWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, MemoryBytes: 64 << 20},
		&ateompb.CheckpointWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, Scope: ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL, SnapshotUri: "s3://bucket/atespaces/ate-demo/actors/" + uid + "/snapshots/1"},
		&ateompb.RestoreWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, Scope: ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL, MemoryBytes: 64 << 20},
		&ateompb.TerminateWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec}
}

// ship does atelet's part: the checkpoint files of one actor on one
// worker become the restore files of an actor on another (or the same).
func ship(t *testing.T, from herder.Paths, fromUID string, files []string, to herder.Paths, toUID string) int64 {
	t.Helper()
	dst := to.RestoreStateDir(toUID)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(from.CheckpointStateDir(fromUID), f))
		if err != nil {
			t.Fatalf("checkpoint file %s: %v", f, err)
		}
		total += int64(len(b))
		if err := os.WriteFile(filepath.Join(dst, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return total
}

func TestActorLifecycleAcrossWorkers(t *testing.T) {
	bin, cgRoot := zygote(t)
	ctx := context.Background()
	base := t.TempDir()
	a := newWorker(t, "worker-a", bin, cgRoot, filepath.Join(base, "node-a"))
	b := newWorker(t, "worker-b", bin, cgRoot, filepath.Join(base, "node-b"))

	// Run the golden boot on A: the template's first actor.
	run, ckpt, _, _ := actorReq("golden")
	t0 := time.Now()
	if _, err := a.svc.RunWorkload(ctx, run); err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("RunWorkload (template warmed, first clone, readyz): %s", time.Since(t0).Round(time.Millisecond))
	if st, body := a.through(t, "GET", "ate-demo/counter-golden", "/count"); st != 200 || body != "0" {
		t.Fatalf("golden count through the ingress = %d %q", st, body)
	}
	for deadline := time.Now().Add(5 * time.Second); !a.home.Ready(); {
		if time.Now().After(deadline) {
			t.Fatal("the home must be ready once its template warmed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A second run on the same worker is refused: one actor per worker.
	run2, _, _, _ := actorReq("second")
	if _, err := a.svc.RunWorkload(ctx, run2); err == nil {
		t.Fatal("a second actor on a busy worker must be refused")
	}
	// Checkpoint the golden state.
	t0 = time.Now()
	resp, err := a.svc.CheckpointWorkload(ctx, ckpt)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	t.Logf("CheckpointWorkload (park, export): %s, files %v", time.Since(t0).Round(time.Millisecond), resp.GetSnapshotFiles())
	if st, _ := a.through(t, "GET", "ate-demo/counter-golden", "/count"); st != http.StatusMisdirectedRequest {
		t.Fatalf("a checkpointed actor must be misdirected, got %d", st)
	}
	if _, _, _, ok := a.svc.Active(); ok {
		t.Fatal("worker A still busy after checkpoint")
	}

	// Actor x1 on worker B is restored from the golden snapshot (atelet
	// downloaded it into x1's restore-state): a new session from the
	// template's state. Then it counts to three and is checkpointed.
	_, ckptX, restoreX, _ := actorReq("x1")
	shipped := ship(t, a.paths, "golden", resp.GetSnapshotFiles(), b.paths, "x1")
	t.Logf("shipped %d bytes", shipped)
	t0 = time.Now()
	if _, err := b.svc.RestoreWorkload(ctx, restoreX); err != nil {
		t.Fatalf("restore x1 on B: %v", err)
	}
	t.Logf("RestoreWorkload from golden (import, claim, resume, readyz): %s", time.Since(t0).Round(time.Millisecond))
	for i := 0; i < 3; i++ {
		if st, _ := b.through(t, "POST", "ate-demo/counter-x1", "/incr"); st != 200 {
			t.Fatalf("incr %d: %d", i, st)
		}
	}
	if st, body := b.through(t, "GET", "ate-demo/counter-x1", "/count"); st != 200 || body != "3" {
		t.Fatalf("x1 count = %d %q, want 3", st, body)
	}
	if _, err := b.svc.GetWorkloadStats(ctx, &ateompb.GetWorkloadStatsRequest{ActorUid: "x1"}); err != nil {
		time.Sleep(100 * time.Millisecond)
		if _, err := b.svc.GetWorkloadStats(ctx, &ateompb.GetWorkloadStatsRequest{ActorUid: "x1"}); err != nil {
			t.Fatalf("stats: %v", err)
		}
	}
	respX, err := b.svc.CheckpointWorkload(ctx, ckptX)
	if err != nil {
		t.Fatalf("checkpoint x1: %v", err)
	}

	// x1 resumes on A (its snapshot travelled back) with the count.
	shipped = ship(t, b.paths, "x1", respX.GetSnapshotFiles(), a.paths, "x1")
	t.Logf("shipped %d bytes", shipped)
	t0 = time.Now()
	if _, err := a.svc.RestoreWorkload(ctx, restoreX); err != nil {
		t.Fatalf("restore x1 on A: %v", err)
	}
	t.Logf("RestoreWorkload of a counted actor: %s", time.Since(t0).Round(time.Millisecond))
	if st, body := a.through(t, "GET", "ate-demo/counter-x1", "/count"); st != 200 || body != "3" {
		t.Fatalf("x1 count on A = %d %q, want 3", st, body)
	}
	_, _, _, termX := actorReq("x1")
	if _, err := a.svc.TerminateWorkload(ctx, termX); err != nil {
		t.Fatalf("terminate x1: %v", err)
	}

	// A second actor from the same golden snapshot starts at zero, not at
	// three: golden state is shared, actor state is not.
	_, _, restoreY, termY := actorReq("y1")
	ship(t, a.paths, "golden", resp.GetSnapshotFiles(), b.paths, "y1")
	if _, err := b.svc.RestoreWorkload(ctx, restoreY); err != nil {
		t.Fatalf("restore y1 on B: %v", err)
	}
	if st, body := b.through(t, "GET", "ate-demo/counter-y1", "/count"); st != 200 || body != "0" {
		t.Fatalf("y1 count = %d %q, want 0", st, body)
	}
	if _, err := b.svc.TerminateWorkload(ctx, termY); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := b.svc.Active(); ok {
		t.Fatal("worker B still busy after terminate")
	}
}
