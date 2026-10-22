//go:build linux && integration

package substratetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/sdk/go/client"

	"github.com/helayoty/fiberd/examples/substrate/herder"
	subhome "github.com/helayoty/fiberd/examples/substrate/home"
	"github.com/helayoty/fiberd/examples/substrate/ingress"
	ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"
)

// The whole worker, in process, driven the way atelet drives it: a
// fiberd over a sandbox backend with a file delta registry, the substrate
// home minting grants and serving its keys, the ingress in front, and
// fake atelet directories under a temp root. The image's backend is
// gVisor, so that is the path the lifecycle runs on first. The proc
// backend runs the same lifecycle, as proof that the herder is a plain
// consumer and takes no backend for granted. Needs the dev container (a
// writable cgroup root, gcc, runsc, criu). The unit side of the herder
// stays beside it in herder_test.go and herder_internal_test.go.

// workerKeys are the delta keys every worker shares. A pool's workers must
// share them so a snapshot taken on one restores on another.
var workerKeys = sync.OnceValue(func() artifact.Keys {
	k, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		panic(err)
	}
	sk, err := artifact.GenerateSealKey()
	if err != nil {
		panic(err)
	}
	seal, err := artifact.SealKeyFromJWK(sk)
	if err != nil {
		panic(err)
	}
	return artifact.Keys{Signer: k, Seal: seal}
})

// work holds every worker's state. Not a tmpfs: gVisor's template and
// park images would be memory there.
const work = "/var/lib/fiberd-test/substrate"

// backendCase is one sandbox backend the worker can run on: how to open
// it under a state directory and the template command it runs.
type backendCase struct {
	name     string
	open     func(t *testing.T, stateDir string) backend.Backend
	template string
}

// gvisorRootfs builds the rootfs every sandbox runs in, once, the way the
// image does (hack/gvisor/rootfs.sh), or skips without runsc.
var gvisorRootfs = sync.OnceValues(func() (string, error) {
	if _, err := exec.LookPath("runsc"); err != nil {
		return "", err
	}
	dir := filepath.Join(work, "rootfs")
	_ = os.RemoveAll(dir)
	build := exec.Command("../../../hack/gvisor/rootfs.sh", dir)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("hack/gvisor/rootfs.sh: %w", err)
	}
	return dir, nil
})

// procZygote builds refzygote for the proc backend, once.
var procZygote = sync.OnceValues(func() (string, error) {
	bin := filepath.Join(work, "refzygote")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return "", err
	}
	// The zygote library first, cargo run in its crate so rustup takes the
	// toolchain it pins, then linked as an archive.
	core := exec.Command("cargo", "build", "--release", "--locked")
	core.Dir = "../../../sdk/c/template/core"
	if out, err := core.CombinedOutput(); err != nil {
		return "", fmt.Errorf("cargo: %w: %s", err, out)
	}
	args := []string{"-O2", "-pthread"}
	// As in the Makefile's ZYGOTE_CFLAGS, arm64 builds take no pointer
	// authentication, since a restored process keeps stale PAC keys.
	if runtime.GOARCH == "arm64" {
		args = append(args, "-mbranch-protection=none")
	}
	build := exec.Command("gcc", append(args, "-o", bin, "../../../sdk/c/template/refzygote.c",
		"../../../sdk/c/template/core/target/release/libfiberzygote_core.a")...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("gcc: %w", err)
	}
	return bin, nil
})

// plainCounter builds bench/compare's counter for the Move baseline,
// once, with refzygote's flags above. Its --plain mode is a plain process
// serving the same /readyz and /count as refzygote --http, after the same
// init: the heap touched page by page and the same CPU burn. It links the
// zygote library, which procZygote builds, though --plain never calls it.
var plainCounter = sync.OnceValues(func() (string, error) {
	if _, err := procZygote(); err != nil {
		return "", err
	}
	bin := filepath.Join(work, "counter")
	args := []string{"-O2", "-pthread"}
	if runtime.GOARCH == "arm64" {
		args = append(args, "-mbranch-protection=none")
	}
	build := exec.Command("gcc", append(args, "-o", bin, "../../../bench/compare/workload/counter.c",
		"../../../sdk/c/template/core/target/release/libfiberzygote_core.a")...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("gcc: %w", err)
	}
	return bin, nil
})

// backends are the cases the lifecycle runs on: the image's, then proc.
func backends() []backendCase {
	return []backendCase{
		{name: "gvisor", template: "/bin/refzygote --heap-mb 8 --gvisor --http",
			open: func(t *testing.T, stateDir string) backend.Backend {
				rootfs, err := gvisorRootfs()
				if err != nil {
					t.Skipf("gvisor backend not usable here: %v", err)
				}
				return gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: stateDir})
			}},
		{name: "proc", open: func(t *testing.T, _ string) backend.Backend {
			if _, err := procZygote(); err != nil {
				t.Skipf("cannot build refzygote: %v", err)
			}
			return procbackend.New(procbackend.Options{})
		}},
	}
}

// templateOf is the case's template command (proc's names the binary it built).
func (bc backendCase) templateOf(t *testing.T) string {
	if bc.template != "" {
		return bc.template
	}
	bin, err := procZygote()
	if err != nil {
		t.Skip(err)
	}
	return bin + " --heap-mb 8 --http"
}

// worker is one Substrate worker Pod's worth of fiberd.
type worker struct {
	name    string
	svc     *herder.Service
	home    *subhome.Home
	ingress *httptest.Server
	paths   herder.Paths
}

func newWorker(t *testing.T, name string, bc backendCase, cgRoot, base string) *worker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	state := filepath.Join(work, fmt.Sprintf("%s-%s-%d", bc.name, name, time.Now().UnixNano()%1_000_000))
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })

	// The home: its own issuer on a loopback server.
	isrv := httptest.NewServer(nil)
	t.Cleanup(isrv.Close)
	h, err := subhome.New(subhome.Config{Audience: name, IssuerURL: isrv.URL, CgroupRoot: filepath.Join(cgRoot, name+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		Isolation: core.Trusted})
	if err != nil {
		t.Fatal(err)
	}
	isrv.Config.Handler = h.Handler()

	// fiberd over the case's backend, publishing to a file registry.
	hc := host.Config{
		Backend:       bc.open(t, filepath.Join(state, "backend")),
		Templates:     map[string]string{"default": bc.templateOf(t)},
		CgroupRoot:    h.CgroupRoot(),
		RunDir:        filepath.Join("/tmp", "fz-"+name),
		DeltaDir:      filepath.Join(state, "deltas"),
		TemplateCache: filepath.Join(state, "templates"),
		DeltaRegistry: artifact.FileScheme + filepath.Join(state, "registry"),
		DeltaKeys:     workerKeys(),
		HomeID:        name,
	}
	rt, err := host.New(hc)
	if errors.Is(err, host.ErrNoTier) {
		t.Skipf("%s backend not usable here: %v", bc.name, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		rt.Close()
		_ = os.RemoveAll(hc.RunDir)
	})
	if rt.Tier() < core.TierCheckpoint {
		t.Skipf("%s backend cannot park here (tier %s)", bc.name, rt.Tier())
	}
	ag := &core.Core{
		NodeID: name, Ledger: core.NewLedger(1), RateLimit: core.NewRateLimit(1000, 1<<20),
		Runtime: rt, Verify: &grant.Verifier{Cache: &grant.Cache{IssuerURL: isrv.URL}, Audience: name, MaxStale: time.Hour},
		Health: h.Health(), StatusInterval: 20 * time.Millisecond,
	}
	go ag.Run(ctx)
	go fhome.Drive(ctx, h, ag) // delivery: minted grants are admitted and warmed, readiness published
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Core: ag, Issuer: isrv.URL, RetryAfter: time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := client.New(conn)

	ing, err := ingress.New(ingress.Config{})
	if err != nil {
		t.Fatal(err)
	}
	isrv2 := httptest.NewServer(ing)
	t.Cleanup(isrv2.Close)

	paths := herder.Paths{Base: base}
	svc := herder.New(herder.Config{Client: c, Grants: h, Router: ing, Paths: paths,
		Host: host.Config{DeltaRegistry: hc.DeltaRegistry, DeltaKeys: hc.DeltaKeys, HomeID: name}})
	go svc.Run(ctx)
	return &worker{name: name, svc: svc, home: h, ingress: isrv2, paths: paths}
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
	spec := &ateompb.WorkloadSpec{Containers: []*ateompb.Container{{Name: "counter", WakeupProbe: &ateompb.WakeupProbe{HttpGet: &ateompb.HttpGetAction{Path: "/readyz", Port: 80}}}}}
	id := func() (string, string, string, string, string) {
		return "ate-demo", "counter-" + uid, uid, "ate-demo", "counter"
	}
	as, an, au, ta, tn := id()
	return &ateompb.RunWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, MemoryBytes: 64 << 20},
		&ateompb.CheckpointWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, Fidelity: ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, SnapshotUri: "s3://bucket/atespaces/ate-demo/actors/" + uid + "/snapshots/1"},
		&ateompb.RestoreWorkloadRequest{Atespace: as, ActorName: an, ActorUid: au, ActorTemplateAtespace: ta, ActorTemplateName: tn, Spec: spec, Fidelity: ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, MemoryBytes: 64 << 20},
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

// snapshot is a checkpoint's files on the worker that wrote them.
type snapshot struct {
	on    *worker
	files []string
}

// TestActorLifecycleAcrossWorkers runs the lifecycle on each backend.
func TestActorLifecycleAcrossWorkers(t *testing.T) {
	for _, bc := range backends() {
		t.Run(bc.name, func(t *testing.T) { lifecycleAcrossWorkers(t, bc, cgRoot) })
	}
}

func lifecycleAcrossWorkers(t *testing.T, bc backendCase, cgRoot string) {
	ctx := context.Background()
	base := t.TempDir()
	a := newWorker(t, "worker-a", bc, cgRoot, filepath.Join(base, "node-a"))
	b := newWorker(t, "worker-b", bc, cgRoot, filepath.Join(base, "node-b"))

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
	// Checkpoint the golden state, which the actors below start from.
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
	snapshots := map[string]snapshot{"golden": {on: a, files: resp.GetSnapshotFiles()}} // by actor uid

	// The Move baseline, without fiberd: the same counter started as a
	// plain process on B's side, timed from its start to the first 200 on
	// /readyz, polled as the herder polls. It starts empty, so its count
	// is 0 whatever the actor had counted. Every real platform adds to a
	// process start, so this is a lower bound, and it leaves out
	// rebuilding the lost state. The fiberd side is each restore below.
	t.Run("a plain counter started on B's side, without fiberd, starts empty", func(t *testing.T) {
		bin, err := plainCounter()
		if err != nil {
			t.Skipf("cannot build bench/compare's counter: %v", err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		cmd := exec.Command(bin, "--plain", "--heap-mb", "8", "--port", strconv.Itoa(port))
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		t0 := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		base := fmt.Sprintf("http://127.0.0.1:%d", port)
		ready, err := firstOK(base+"/readyz", 30*time.Second)
		if err != nil {
			t.Fatalf("plain counter: %v", err)
		}
		took := ready.Sub(t0)
		st, count := get(t, base+"/count")
		if st != 200 || count != "0" {
			t.Fatalf("plain counter count = %d %q, want 200 0: a new process starts empty", st, count)
		}
		t.Log(moveLine("plain", bc.name, "-", "-", b.name, took, count, false))
	})

	// Each step is atelet moving an actor. It restores the actor on a
	// worker from a downloaded snapshot, drives its count through the
	// ingress, then removes it by checkpoint, whose snapshot a later step
	// uses, or by terminate. Either way the ingress forgets the actor and
	// the worker is free. Steps run in order.
	cases := []struct {
		name       string
		from       string // the snapshot's actor uid
		to         *worker
		uid        string
		incr       int    // POST /incr after the restore
		count      string // GET /count after that
		checkpoint bool
		readyz     string // a readyz path the actor never answers 200 on, so the restore fails
	}{
		{name: "x1 restores on B from the golden snapshot, a new session from the template's state, and counts to three",
			from: "golden", to: b, uid: "x1", incr: 3, count: "3", checkpoint: true},
		{name: "x1 resumes on A from its own snapshot with its count",
			from: "x1", to: a, uid: "x1", count: "3"},
		{name: "y1 from the same golden snapshot starts at zero: golden state is shared, actor state is not",
			from: "golden", to: b, uid: "y1", count: "0"},
		{name: "z1 restored but never ready is let go: the restore is unavailable and the worker stays free",
			from: "golden", to: a, uid: "z1", readyz: "/missing"},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			_, ckpt, restore, term := actorReq(tc.uid)
			actor := "ate-demo/counter-" + tc.uid
			snap := snapshots[tc.from]
			t.Logf("shipped %d bytes", ship(t, snap.on.paths, tc.from, snap.files, tc.to.paths, tc.uid))
			t0 := time.Now()
			if tc.readyz != "" {
				restore.Spec = &ateompb.WorkloadSpec{Containers: []*ateompb.Container{{Name: "counter",
					WakeupProbe: &ateompb.WakeupProbe{HttpGet: &ateompb.HttpGetAction{Path: tc.readyz}, TimeoutSeconds: 1}}}}
				if _, err := tc.to.svc.RestoreWorkload(ctx, restore); status.Code(err) != codes.Unavailable {
					t.Fatalf("restore %s with readyz %s = %v, want Unavailable", tc.uid, tc.readyz, err)
				}
				if st, _ := tc.to.through(t, "GET", actor, "/count"); st != http.StatusMisdirectedRequest {
					t.Fatalf("an actor that never turned ready must be misdirected, got %d", st)
				}
				if _, _, _, ok := tc.to.svc.Active(); ok {
					t.Fatal("worker busy with an actor that never turned ready")
				}
				return
			}
			if _, err := tc.to.svc.RestoreWorkload(ctx, restore); err != nil {
				t.Fatalf("restore %s: %v", tc.uid, err)
			}
			took := time.Since(t0)
			t.Logf("RestoreWorkload (import, claim, resume, readyz): %s", took.Round(time.Millisecond))
			// The count the actor parked with, read before it counts on.
			total, err := strconv.Atoi(tc.count)
			if err != nil {
				t.Fatal(err)
			}
			parkedWith := strconv.Itoa(total - tc.incr)
			if st, body := tc.to.through(t, "GET", actor, "/count"); st != 200 || body != parkedWith {
				t.Fatalf("%s count right after the restore = %d %q, want %s", tc.uid, st, body, parkedWith)
			}
			t.Log(moveLine("fiberd", bc.name, tc.uid, tc.from, tc.to.name, took, parkedWith, true))
			for i := 0; i < tc.incr; i++ {
				if st, _ := tc.to.through(t, "POST", actor, "/incr"); st != 200 {
					t.Fatalf("incr %d: %d", i, st)
				}
			}
			if st, body := tc.to.through(t, "GET", actor, "/count"); st != 200 || body != tc.count {
				t.Fatalf("%s count = %d %q, want %s", tc.uid, st, body, tc.count)
			}
			if _, err := tc.to.svc.GetWorkloadStats(ctx, &ateompb.GetWorkloadStatsRequest{ActorUid: tc.uid}); err != nil {
				time.Sleep(100 * time.Millisecond)
				if _, err := tc.to.svc.GetWorkloadStats(ctx, &ateompb.GetWorkloadStatsRequest{ActorUid: tc.uid}); err != nil {
					t.Fatalf("stats: %v", err)
				}
			}
			if tc.checkpoint {
				resp, err := tc.to.svc.CheckpointWorkload(ctx, ckpt)
				if err != nil {
					t.Fatalf("checkpoint %s: %v", tc.uid, err)
				}
				snapshots[tc.uid] = snapshot{on: tc.to, files: resp.GetSnapshotFiles()}
			} else if _, err := tc.to.svc.TerminateWorkload(ctx, term); err != nil {
				t.Fatalf("terminate %s: %v", tc.uid, err)
			}
			if st, _ := tc.to.through(t, "GET", actor, "/count"); st != http.StatusMisdirectedRequest {
				t.Fatalf("an actor taken off must be misdirected, got %d", st)
			}
			if _, _, _, ok := tc.to.svc.Active(); ok {
				t.Fatal("worker still busy after the actor left")
			}
		}) {
			t.FailNow()
		}
	}
}

// firstOK polls url until it answers 200, every 50 ms with a 2 s request
// timeout as the herder's readiness probe does, and returns when.
func firstOK(url string, within time.Duration) (time.Time, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(within)
	for {
		resp, err := c.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return time.Now(), nil
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			return time.Time{}, fmt.Errorf("%s did not answer 200 within %s: %w", url, within, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// get is one plain GET, its status and trimmed body.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}
