//go:build linux

package proctest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

// newHost opens the host runtime over the fork backend, as fiberd
// -runtime proc does. A fiber that cannot get its namespaces or drop its
// privileges is refused. A caller may pass its own fork backend, such as a
// timed one for the benchmarks.
func newHost(c host.Config) (core.Runtime, error) {
	if c.Backend == nil {
		c.Backend = procbackend.New(procbackend.Options{})
	}
	c.FiberHide = append(c.FiberHide, hiddenDir)
	if c.Handoff == nil {
		// Routes handoff fibers without listening. Tests hand them
		// connections through Deliver.
		c.Handoff = &handoff.Router{}
		c.HandoffKey = make([]byte, 32)
		if _, err := rand.Read(c.HandoffKey); err != nil {
			return nil, err
		}
	}
	if c.DeltaRegistry != "" && c.DeltaKeys.Signer == nil {
		c.DeltaKeys = deltaKeys
	}
	return host.New(c)
}

var (
	zygoteBin string
	cgRoot    = os.Getenv("FIBERD_CGROUP_ROOT")
	// hiddenDir holds a secret the agent can read and no fiber may.
	hiddenDir string
	// deltaKeys are the keys every test home signs, trusts and seals
	// deltas with, as a deployment's homes share them.
	deltaKeys artifact.Keys
)

// zygoteBuildFlags mirrors ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS in the
// Makefile, so the tests run the zygote hardened as it ships. On arm64
// that includes -mbranch-protection=none, because a restored process
// keeps stale pointer-authentication keys. goarch is runtime.GOARCH.
func zygoteBuildFlags(goarch string) []string {
	flags := []string{"-D_FORTIFY_SOURCE=3", "-O2", "-fstack-protector-strong", "-fstack-clash-protection", "-fPIE",
		"-Wformat=2", "-Werror=format-security"}
	if goarch == "arm64" {
		flags = append(flags, "-mbranch-protection=none")
	}
	return append(flags, "-pie", "-Wl,-z,relro,-z,now")
}

// TestZygoteBuildFlags pins the arm64 flag that keeps pointer
// authentication out of the zygote the tests build. Without it a restored
// fiber traps on a FEAT_FPAC CPU, and some toolchains default to
// -mbranch-protection=standard.
func TestZygoteBuildFlags(t *testing.T) {
	cases := []struct {
		name   string
		goarch string
		want   bool
	}{
		{name: "arm64 disables branch protection", goarch: "arm64", want: true},
		{name: "amd64 has no such flag", goarch: "amd64", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Contains(zygoteBuildFlags(tc.goarch), "-mbranch-protection=none")
			if got != tc.want {
				t.Fatalf("zygoteBuildFlags(%q) has -mbranch-protection=none: %v, want %v", tc.goarch, got, tc.want)
			}
		})
	}
}

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping proc tests: %s not writable (run under make linux-test)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	dir, err := os.MkdirTemp("", "refzygote")
	if err != nil {
		panic(err)
	}
	zygoteBin = filepath.Join(dir, "refzygote")
	args := append(zygoteBuildFlags(runtime.GOARCH),
		"-pthread", "-DFZ_TLS", "-o", zygoteBin, "../../zygote/refzygote.c", "../../zygote/libfiberzygote.c", "-lssl", "-lcrypto")
	build := exec.Command("gcc", args...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping proc tests: cannot build refzygote: %v\n", err)
		os.Exit(0)
	}
	hiddenDir = filepath.Join(dir, "hidden")
	if err := os.MkdirAll(hiddenDir, 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "secret"), []byte("agent only\n"), 0o600); err != nil {
		panic(err)
	}
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
	deltaKeys = artifact.Keys{Signer: k, Seal: seal}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newRuntime(t *testing.T) core.Runtime {
	t.Helper()
	return newRuntimeWith(t, nil)
}

// newRuntimeWith is newRuntime over the given backend (nil for the
// default fork backend).
func newRuntimeWith(t *testing.T, be backend.Backend) core.Runtime {
	t.Helper()
	return newRuntimeFrom(t, be, zygoteBin+" --heap-mb 32")
}

// newRuntimeFrom is newRuntimeWith over the given template command line
// (an argv, so a wrapper may be prefixed to the zygote).
func newRuntimeFrom(t *testing.T, be backend.Backend, template string) core.Runtime {
	t.Helper()
	run := filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()))
	rt, err := newHost(host.Config{
		Backend:    be,
		Templates:  map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("t%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:     run,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
		if t.Failed() {
			logs, _ := filepath.Glob(filepath.Join(run, "*", "zygote.log"))
			for _, l := range logs {
				if b, err := os.ReadFile(l); err == nil {
					t.Logf("%s:\n%s", l, b)
				}
			}
		}
		_ = os.RemoveAll(run)
	})
	return rt
}

// peerPID is the host pid of the process serving a unix endpoint, from
// the connection's peer credentials.
func peerPID(t *testing.T, endpoint string) int {
	t.Helper()
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := fiberendpoint.Dial(dctx, endpoint)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		t.Fatalf("%s is not a unix socket", endpoint)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil {
		t.Fatalf("peer credentials of %s: %v %v", endpoint, err, credErr)
	}
	return int(cred.Pid)
}

// talk sends one line to a fiber's endpoint and returns the reply.
func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := fiberendpoint.Dial(dctx, endpoint)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	return talkOver(t, c, line)
}

// handOff connects to a handoff fiber the way the agent does. One end of
// a fresh socket pair is passed to the fiber, and the other is returned
// as the caller's TLS client, presenting cert.
func handOff(t *testing.T, rt core.Runtime, fiberID string, cert tls.Certificate) net.Conn {
	t.Helper()
	key, pin, ok := rt.(core.HandoffRouter).HandoffRoute(fiberID)
	if !ok || pin == "" {
		t.Fatalf("no handoff route for %s", fiberID)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(fds[1]), "handed")
	defer func() { _ = theirs.Close() }()
	if err := rt.(interface {
		Deliver(string, *os.File) error
	}).Deliver(fiberID, theirs); err != nil {
		_ = syscall.Close(fds[0])
		t.Fatalf("deliver to %s: %v", fiberID, err)
	}
	ours := os.NewFile(uintptr(fds[0]), "ours")
	defer func() { _ = ours.Close() }()
	c, err := net.FileConn(ours)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Client(c, handoff.ClientConfig(key, pin, cert))
}

// callerCert is a self-signed client certificate and its x5t#S256.
func callerCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, tlsconf.Thumbprint(leaf)
}

// talkOver sends one line on c, returns the reply and closes c.
func talkOver(t *testing.T, c net.Conn, line string) string {
	t.Helper()
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply to %q: %v", line, err)
	}
	return strings.TrimSpace(reply)
}

func TestCloneServeStatsRelease(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("second prepare must be idempotent: %v", err)
	}
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	t0 := time.Now()
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fork-to-ready: %s", time.Since(t0))
	if h.ID != "g1/1/1" || !strings.HasPrefix(h.Endpoint, "unix://") {
		t.Fatalf("handle = %+v", h)
	}
	if got := talk(t, h.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	if got := talk(t, h.Endpoint, "fence"); got != "g1/1/1" {
		t.Fatalf("fence = %q, want the identity assigned after the fork", got)
	}
	// Identity lives only in the child: the environment was scrubbed and
	// the fence set afterwards. (Asked of the process itself: the kernel's
	// /proc/<pid>/environ shows the exec-time block, not what clearenv did.)
	if got := talk(t, h.Endpoint, "getenv FIBERD_FENCE"); got != "g1/1/1" {
		t.Fatalf("FIBERD_FENCE in child = %q", got)
	}
	for _, name := range []string{"PATH", "FIBERD_GRANT", "HOME"} {
		if got := talk(t, h.Endpoint, "getenv "+name); got != "-" {
			t.Fatalf("%s survived the scrub: %q", name, got)
		}
	}

	before, _ := rt.Stats(ctx, h.ID)
	if got := talk(t, h.Endpoint, "dirty 8388608"); got != "ok 8388608" {
		t.Fatalf("dirty = %q", got)
	}
	after, _ := rt.Stats(ctx, h.ID)
	if after.WUsedBytes < before.WUsedBytes+7<<20 {
		t.Fatalf("W before=%d after=%d, want >= 8 MiB growth from dirtying (CoW charged to the leaf)", before.WUsedBytes, after.WUsedBytes)
	}
	t.Logf("W before=%d after=%d", before.WUsedBytes, after.WUsedBytes)

	if got := talk(t, h.Endpoint, "incr"); got != "1" {
		t.Fatalf("incr = %q", got)
	}
	list, err := rt.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != h.ID {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := rt.Release(ctx, h.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case ex := <-rt.Exits():
		t.Fatalf("release must not report an exit, got %+v", ex)
	case <-time.After(200 * time.Millisecond):
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after release list = %+v", list)
	}
	if _, err := os.Stat(fiberendpoint.UnixPath(h.Endpoint)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint not cleaned: %v", err)
	}
}

func TestParkResumeKeepsState(t *testing.T) {
	caller, callerX5t := callerCert(t)
	stranger, _ := callerCert(t)
	cases := []struct {
		name string
		mode core.EndpointMode
		// callerX5t binds the grant to the caller's certificate.
		callerX5t string
		// say sends one line to the fiber and returns the reply.
		say func(t *testing.T, rt core.Runtime, h core.FiberHandle, line string) string
		// refused, when set, is a connection the fiber must turn away.
		refused func(t *testing.T, rt core.Runtime, h core.FiberHandle)
		// fenceFile is where the resumed fiber's new fence is published.
		fenceFile func(h core.FiberHandle) string
	}{
		{
			name: "direct",
			mode: core.EndpointDirect,
			say: func(t *testing.T, _ core.Runtime, h core.FiberHandle, line string) string {
				return talk(t, h.Endpoint, line)
			},
			fenceFile: func(h core.FiberHandle) string { return fiberendpoint.UnixPath(h.Endpoint) + ".fence" },
		},
		{
			// The fiber never listens and terminates TLS itself. Its
			// channel to the host is external to the checkpoint and
			// replaced on resume.
			name:      "handoff",
			mode:      core.EndpointHandoff,
			callerX5t: callerX5t,
			say: func(t *testing.T, rt core.Runtime, h core.FiberHandle, line string) string {
				return talkOver(t, handOff(t, rt, h.ID, caller), line)
			},
			refused: func(t *testing.T, rt core.Runtime, h core.FiberHandle) {
				c := handOff(t, rt, h.ID, stranger)
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := fmt.Fprintln(c, "get"); err == nil {
					if reply, err := bufio.NewReader(c).ReadString('\n'); err == nil {
						t.Fatalf("a stranger's certificate was served: %q", reply)
					}
				}
			},
			fenceFile: func(core.FiberHandle) string {
				return filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()), "g5", "1-2.fence")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here; runtime offers", rt.Tier())
			}
			var refused func(core.FiberHandle)
			if tc.refused != nil {
				refused = func(h core.FiberHandle) { tc.refused(t, rt, h) }
			}
			parkResumeKeepsState(t, rt, tc.mode, tc.callerX5t, func(h core.FiberHandle, line string) string { return tc.say(t, rt, h, line) }, refused, tc.fenceFile)
		})
	}
}

func parkResumeKeepsState(t *testing.T, rt core.Runtime, mode core.EndpointMode, callerX5t string, say func(core.FiberHandle, string) string, refused func(core.FiberHandle), fenceFile func(core.FiberHandle) string) {
	ctx := context.Background()
	g := core.Grant{UID: "g5", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20, CallerThumbprint: callerX5t, Policy: core.Policy{EndpointMode: mode}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	f1 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 1}
	h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: f1, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	say(h1, "incr")
	if refused != nil {
		refused(h1)
	}
	if got := say(h1, "incr"); got != "2" {
		t.Fatalf("incr = %q", got)
	}

	// Sync park: images durable, then the incarnation ends. No exit is
	// reported (it was ours), the leaf and endpoint are gone.
	t0 := time.Now()
	ref, err := rt.Park(ctx, h1.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	t.Logf("park (sync): %s -> %s", time.Since(t0), ref)
	select {
	case ex := <-rt.Exits():
		t.Fatalf("park must not report an exit, got %+v", ex)
	case <-time.After(200 * time.Millisecond):
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after park list = %+v", list)
	}
	if _, err := os.Stat(filepath.Join(ref, "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}

	// Resume under a new fence: the counter survived, the endpoint is the
	// one the process bound, the new fence is published beside it.
	f2 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 2}
	t0 = time.Now()
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: f2, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("resume: %s", time.Since(t0))
	if h2.ID != "g5/1/2" || h2.Endpoint != h1.Endpoint {
		t.Fatalf("resumed handle = %+v (first %+v)", h2, h1)
	}
	if got := say(h2, "get"); got != "2" {
		t.Fatalf("counter after resume = %q, want 2 (state must survive park/resume)", got)
	}
	if got := say(h2, "incr"); got != "3" {
		t.Fatalf("incr after resume = %q", got)
	}
	pub, _ := os.ReadFile(fenceFile(h2))
	if strings.TrimSpace(string(pub)) != "g5/1/2" {
		t.Fatalf("published fence = %q", pub)
	}
	if st, err := rt.Stats(ctx, h2.ID); err != nil || st.WUsedBytes == 0 {
		t.Fatalf("stats after resume = %+v %v", st, err)
	}

	// Park again without sync, resume again, then release with discard.
	ref2, err := rt.Park(ctx, h2.ID, false)
	if err != nil {
		t.Fatalf("second park: %v", err)
	}
	f3 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 3}
	h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref2, Fence: f3, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if got := say(h3, "get"); got != "3" {
		t.Fatalf("counter after second resume = %q, want 3", got)
	}
	if err := rt.Release(ctx, h3.ID, true); err != nil {
		t.Fatal(err)
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after release list = %+v", list)
	}
}

func TestOrphanAdoptionAcrossRuntimes(t *testing.T) {
	// A fiber left by a previous agent: a second runtime over the same
	// cgroup root must see it in List and be able to kill it by id.
	root := filepath.Join(cgRoot, "t"+fmt.Sprint(time.Now().UnixNano()%1_000_000))
	run := filepath.Join("/tmp", "fz-orphan")
	mk := func() core.Runtime {
		rt, err := newHost(host.Config{Templates: map[string]string{"default": zygoteBin + " --heap-mb 16"}, CgroupRoot: root, RunDir: run})
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	ctx := context.Background()
	g := core.Grant{UID: "g6", TemplateDigest: "sha256:ref"}
	rt1 := mk()
	if err := rt1.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt1.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g6", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Second runtime, same root, no knowledge of rt1's fibers.
	rt2 := mk()
	list, err := rt2.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != h.ID {
		t.Fatalf("second runtime list = %+v %v, want the orphan %s", list, err, h.ID)
	}
	if err := rt2.Release(ctx, h.ID, false); err != nil {
		t.Fatalf("release orphan: %v", err)
	}
	if list, _ := rt2.List(ctx); len(list) != 0 {
		t.Fatalf("orphan still listed: %+v", list)
	}
	if dc, ok := rt2.(core.DeltaChecker); !ok || dc.HasDelta("/nonexistent") {
		t.Fatal("HasDelta must report a missing delta as missing")
	}
	if c, ok := rt1.(interface{ Close() }); ok {
		c.Close()
	}
	_ = os.RemoveAll(run)
}

func TestParkIsWSizedDelta(t *testing.T) {
	rt := newRuntime(t)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	ctx := context.Background()
	g := core.Grant{UID: "g9", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g9", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Born or resumed, a fiber is the init of its own pid namespace,
	// without capabilities it could use or regain, and blind to what the
	// agent hides in its mount namespace.
	secret := filepath.Join(hiddenDir, "secret")
	if b, err := os.ReadFile(secret); err != nil || len(b) == 0 {
		t.Fatalf("the agent cannot read its own secret: %v", err)
	}
	confined := []struct{ cmd, want string }{
		{cmd: "pid", want: "1"},
		{cmd: "status CapEff", want: "0000000000000000"},
		{cmd: "status CapBnd", want: "0000000000000000"},
		{cmd: "status NoNewPrivs", want: "1"},
		{cmd: "read " + secret, want: "-"},
	}
	probe := func(when, endpoint string) {
		t.Helper()
		for _, p := range confined {
			if got := talk(t, endpoint, p.cmd); got != p.want {
				t.Fatalf("%s: %s = %q, want %q", when, p.cmd, got, p.want)
			}
		}
	}
	probe("born", h.Endpoint)

	// Neither sibling sees the other's processes, and each has a mount
	// namespace of its own, apart from the agent's.
	sib, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g9", Epoch: 1, Seq: 3}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pid, sibPID := peerPID(t, h.Endpoint), peerPID(t, sib.Endpoint)
	apart := []struct{ endpoint, cmd string }{
		{endpoint: h.Endpoint, cmd: fmt.Sprintf("read /proc/%d/status", sibPID)},
		{endpoint: sib.Endpoint, cmd: fmt.Sprintf("read /proc/%d/status", pid)},
		{endpoint: h.Endpoint, cmd: "read /proc/2/status"},
	}
	for _, a := range apart {
		if got := talk(t, a.endpoint, a.cmd); got != "-" {
			t.Fatalf("sibling visible: %s = %q, want -", a.cmd, got)
		}
	}
	ns := map[string]bool{}
	for _, p := range []string{"self", fmt.Sprint(pid), fmt.Sprint(sibPID)} {
		link, err := os.Readlink("/proc/" + p + "/ns/mnt")
		if err != nil || ns[link] {
			t.Fatalf("mount namespace of %s = %q (%v), want one of its own", p, link, err)
		}
		ns[link] = true
	}
	// Siblings draw their own randomness. Each fiber's generator is
	// reseeded at birth, so the first values differ instead of repeating
	// what the zygote's seed would give.
	for _, cmd := range []string{"random"} {
		if a, b := talk(t, h.Endpoint, cmd), talk(t, sib.Endpoint, cmd); a == b {
			t.Fatalf("siblings' first %s = %q and %q, want different values", cmd, a, b)
		}
	}
	if err := rt.Release(ctx, sib.ID, true); err != nil {
		t.Fatal(err)
	}

	const dirty = 8 << 20
	talk(t, h.Endpoint, fmt.Sprintf("dirty %d", dirty))
	talk(t, h.Endpoint, "incr")
	t0 := time.Now()
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	parkTook := time.Since(t0)
	var m struct {
		WBytes uint64 `json:"w_bytes"`
		Delta  bool   `json:"delta"`
	}
	b, _ := os.ReadFile(filepath.Join(ref, "manifest.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if !m.Delta {
		t.Fatal("park did not produce a delta")
	}
	// The delta is the dirtied working set: 8 MiB plus a few pages of
	// stack, libc state and socket buffers, well within the plan's 20%.
	lo, hi := uint64(dirty), uint64(dirty+dirty/5)
	if m.WBytes < lo || m.WBytes > hi {
		t.Fatalf("delta W = %d bytes, want within [%d, %d] for %d dirtied", m.WBytes, lo, hi, dirty)
	}
	pages, _ := os.Stat(filepath.Join(ref, "pages-1.img"))
	t.Logf("park (sync) %s: delta %d bytes for %d dirtied (pages file %d bytes, zygote heap 32 MiB)", parkTook.Round(time.Millisecond), m.WBytes, dirty, pages.Size())

	// Resume merges the delta with this home's zygote pages.
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g9", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "1" {
		t.Fatalf("counter after resume = %q, want 1", got)
	}
	probe("resumed", h2.Endpoint)
	_ = rt.Release(ctx, h2.ID, true)
}

// TestFiberCannotWriteHostControls pins that a fiber cannot write host
// sysctls such as core_pattern, a path to host root, or any grant's cgroup
// limits. A fiber is euid 0, and sysctl and kernfs let euid 0 write on the
// owner bit alone, so only its read-only mounts stand in the way. Each
// control must answer EROFS at birth and after a park and resume, because
// CRIU rebuilds the mount namespace.
func TestFiberCannotWriteHostControls(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "gro", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "gro", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// ownCgroup is the cgroup of the fiber serving endpoint. Neither the
	// fiber nor this test has a cgroup namespace, so both see the same
	// path. Each incarnation has a cgroup of its own.
	ownCgroup := func(endpoint string) string {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", peerPID(t, endpoint)))
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if rest, ok := strings.CutPrefix(line, "0::"); ok {
				return filepath.Join("/sys/fs/cgroup", rest)
			}
		}
		return ""
	}
	cases := []struct {
		name, path string
		own        bool // path is relative to the fiber's own cgroup
	}{
		{name: "core_pattern", path: "/proc/sys/kernel/core_pattern"},
		{name: "modprobe", path: "/proc/sys/kernel/modprobe"},
		{name: "cgroup root procs", path: "/sys/fs/cgroup/cgroup.procs"},
		{name: "own memory.max", path: "memory.max", own: true},
	}
	probe := func(when, endpoint string) {
		own := ownCgroup(endpoint)
		for _, tc := range cases {
			t.Run(when+"/"+tc.name, func(t *testing.T) {
				path := tc.path
				if tc.own {
					if own == "" {
						t.Skip("the fiber's cgroup is not visible from here")
					}
					path = filepath.Join(own, tc.path)
				}
				if _, err := os.Stat(path); err != nil {
					t.Skipf("%s: %v", path, err)
				}
				if got := talk(t, endpoint, "wopen "+path); got != "EROFS" {
					t.Errorf("open %s for writing = %q, want EROFS", path, got)
				}
			})
		}
	}
	probe("born", h.Endpoint)
	if rt.Tier() < core.TierCheckpoint {
		_ = rt.Release(ctx, h.ID, true)
		return
	}
	// A sync park ends the born incarnation. The resumed one gets its
	// mount namespace from CRIU and must be as closed.
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "gro", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	probe("resumed", h2.Endpoint)
	_ = rt.Release(ctx, h2.ID, true)
}

func TestResumeOnAnotherRuntimeFromSameArtifact(t *testing.T) {
	// Two homes warmed from the same artifact: a session parked on A
	// resumes on B with its state, because B's zygote pages hash the same
	// as the parent the delta was taken over.
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) core.Runtime {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			CgroupRoot: filepath.Join(cgRoot, name+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+name), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if c, ok := rt.(interface{ Close() }); ok {
				c.Close()
			}
		})
		return rt
	}
	a, b := mk("ha"), mk("hb")
	if a.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	g := core.Grant{UID: "g10", TemplateDigest: digest, WBudgetBytes: 64 << 20}
	if err := a.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := b.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := a.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g10", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		talk(t, h.Endpoint, "incr")
	}
	talk(t, h.Endpoint, "dirty 2097152")
	ref, err := a.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park on A: %v", err)
	}
	var m struct {
		WBytes uint64 `json:"w_bytes"`
		Delta  bool   `json:"delta"`
	}
	mb, _ := os.ReadFile(filepath.Join(ref, "manifest.json"))
	_ = json.Unmarshal(mb, &m)
	t.Logf("parked on A: delta=%v W=%d bytes", m.Delta, m.WBytes)

	h2, err := b.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g10", Epoch: 7, Seq: 1}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume on B: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on B = %q, want 3 (state must move with the delta)", got)
	}
	if got := talk(t, h2.Endpoint, "incr"); got != "4" {
		t.Fatalf("incr on B = %q", got)
	}
	_ = b.Release(ctx, h2.ID, true)
}

// tokenVerifier hands back the grant named by the token: the agents in
// the mobility test share one grant and need no signatures.
type tokenVerifier map[string]core.Grant

func (v tokenVerifier) Verify(_ context.Context, tok []byte) (core.Grant, error) {
	g, ok := v[string(tok)]
	if !ok {
		return core.Grant{}, fmt.Errorf("unknown token %q", tok)
	}
	return g, nil
}

// TestSessionMovesThroughRegistry is the standalone acceptance of phase
// 6: two agents on one host, each with its own runtime warmed from the
// same artifact, a delta registry between them. Count to three on A, park,
// Clone(S) on B resumes with the count, and A no longer believes it holds
// the session.
func TestSessionMovesThroughRegistry(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	// One grant per home (its own uid and audience), the same template:
	// that template is the domain the session moves within.
	grantFor := func(home string) core.Grant {
		return core.Grant{UID: "mob-" + home, Audience: home, TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour),
			Policy: core.Policy{Isolation: core.Trusted}}
	}
	mk := func(home string, keys artifact.Keys) (*core.Agent, core.Runtime) {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			DeltaRegistry: reg + "/deltas", DeltaKeys: keys, HomeID: home,
			CgroupRoot: filepath.Join(cgRoot, home+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+home), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if c, ok := rt.(interface{ Close() }); ok {
				c.Close()
			}
		})
		a := &core.Agent{NodeID: home, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
			Runtime: rt, Verify: tokenVerifier{"g": grantFor(home)},
			Health: core.NewSourceHealth(time.Minute, time.Now())}
		return a, rt
	}
	a, _ := mk("home-a", deltaKeys)
	b, _ := mk("home-b", deltaKeys)
	if b.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}
	domainRepo := reg + "/deltas/" + strings.TrimPrefix(digest, "sha256:")[:40] + "-" + shortHash(digest)

	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("A create: %v %d %v", err, code, r1.Kind)
	}
	for i := 0; i < 3; i++ {
		talk(t, r1.Endpoint, "incr")
	}
	talk(t, r1.Endpoint, "dirty 1048576")
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}
	if _, found, err := artifact.Resolve(ctx, domainRepo+":"+sessionTag("S"), true); err != nil || !found {
		t.Fatalf("delta not published at %s: found=%v err=%v", domainRepo, found, err)
	}

	// A home with a key of its own does not trust A's. It finds S, will
	// not take it, and names no home from the unverified manifest.
	own, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := mk("home-x", artifact.Keys{Signer: own, Seal: deltaKeys.Seal})
	_, code, err = x.Clone(ctx, req)
	var untrusted *core.RemoteMiss
	if code != core.DeferredFallback || !errors.Is(err, artifact.ErrUntrusted) || !errors.As(err, &untrusted) || untrusted.PreferredHome != "" {
		t.Fatalf("untrusting home clone = %d %v, want DeferredFallback ErrUntrusted with no preferred home", code, err)
	}
	if _, found, err := artifact.Resolve(ctx, domainRepo+":"+sessionTag("S"), true); err != nil || !found {
		t.Fatalf("refused session must stay published: found=%v err=%v", found, err)
	}

	t0 := time.Now()
	r2, code, err := b.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("B clone: %v %d", err, code)
	}
	if r2.Kind != core.ActResume {
		t.Fatalf("B clone kind = %v, want RESUME", r2.Kind)
	}
	t.Logf("B claimed and resumed S in %s", time.Since(t0).Round(time.Millisecond))
	if got := talk(t, r2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on B = %q, want 3", got)
	}
	if got := talk(t, r2.Endpoint, "incr"); got != "4" {
		t.Fatalf("incr on B = %q", got)
	}

	// The tag is gone: A's parked copy is stale. A must not resume it.
	r3, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("A clone after claim: %v %d", err, code)
	}
	if r3.Kind != core.ActCreate {
		t.Fatalf("A served a session B holds: kind %v", r3.Kind)
	}
	if got := talk(t, r3.Endpoint, "get"); got != "0" {
		t.Fatalf("A's fresh session counter = %q, want 0", got)
	}
	if code, err := a.Release(ctx, r3.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A release: %v %d", err, code)
	}

	// Too large to move: B parks (4 -> published with W), A is told to
	// prefer home-b.
	if _, code, err := b.Park(ctx, r2.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("B park: %v %d", err, code)
	}
	a.MobilityBudget = func(core.Grant) uint64 { return 4096 }
	_, code, err = a.Clone(ctx, req)
	var rm *core.RemoteMiss
	if code != core.DeferredFallback || !errors.As(err, &rm) || rm.PreferredHome != "home-b" {
		t.Fatalf("A clone of a too-large session = %d %v, want DeferredFallback preferring home-b", code, err)
	}
	// And with the budget back, A pulls it and finds the count at 4.
	a.MobilityBudget = nil
	r4, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r4.Kind != core.ActResume {
		t.Fatalf("A resume from B: %v %d %v", err, code, r4.Kind)
	}
	if got := talk(t, r4.Endpoint, "get"); got != "4" {
		t.Fatalf("counter back on A = %q, want 4", got)
	}
	_, _ = a.Release(ctx, r4.FiberID, true)
}

// TestTemplateParityGate: an artifact's images are only warmed on a host
// they were made on, at the configured strictness. The runtime's own
// platform is overridden to stand in for a different host.
func TestTemplateParityGate(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	here := artifact.Host()
	cases := []struct {
		name     string
		platform artifact.Platform
		parity   artifact.Parity
		wantErr  bool
	}{
		{"same host, strict", artifact.Platform{}, artifact.Strict, false},
		{"other patch release, strict", artifact.Platform{Kernel: here.Kernel + "-other"}, artifact.Strict, true},
		{"other series, series", artifact.Platform{Kernel: "9.9.9"}, artifact.Parity{Kernel: artifact.ParitySeries}, true},
		{"other series, kernel off", artifact.Platform{Kernel: "9.9.9"}, artifact.Parity{Kernel: artifact.ParityOff}, false},
		{"other libc, strict", artifact.Platform{Libc: "(gnu libc) 0.1"}, artifact.Strict, true},
		{"other libc, libc off", artifact.Platform{Libc: "(gnu libc) 0.1"}, artifact.Parity{Libc: artifact.ParityOff}, false},
		{"other arch, everything off", artifact.Platform{Arch: "riscv64"}, artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt, err := newHost(host.Config{
				Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
				CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("par%d-%d", i, time.Now().UnixNano()%1_000_000)),
				RunDir:     filepath.Join("/tmp", fmt.Sprintf("fz-par%d", i)),
				Parity:     c.parity, Platform: c.platform,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.(interface{ Close() }).Close()
			g := core.Grant{UID: fmt.Sprintf("gp%d", i), TemplateDigest: digest}
			err = rt.PrepareTemplate(ctx, g)
			if c.wantErr {
				if !errors.Is(err, host.ErrParity) || !errors.Is(err, artifact.ErrParity) {
					t.Fatalf("prepare = %v, want ErrParity", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			_ = rt.Release(ctx, h.ID, false)
		})
	}
}

// TestMobilityParityGate: a session parked on a host with another kernel
// is found but not taken; the miss names where it is. Relaxing the level
// lets it through.
func TestMobilityParityGate(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	mk := func(home string, parity artifact.Parity, platform artifact.Platform) *core.Agent {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			DeltaRegistry: reg + "/deltas", HomeID: home, Parity: parity, Platform: platform,
			CgroupRoot: filepath.Join(cgRoot, home+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+home), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rt.(interface{ Close() }).Close() })
		g := core.Grant{UID: "par-" + home, Audience: home, TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour),
			Policy: core.Policy{Isolation: core.Trusted}}
		return &core.Agent{NodeID: home, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
			Runtime: rt, Verify: tokenVerifier{"g": g},
			Health: core.NewSourceHealth(time.Minute, time.Now())}
	}
	// home-a believes it runs another kernel (and does not care that its
	// template was built on this one); its deltas say so.
	a := mk("home-a", artifact.Parity{Kernel: artifact.ParityOff}, artifact.Platform{Kernel: "9.9.9-elsewhere"})
	if a.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}
	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("A create: %v %d", err, code)
	}
	for i := 0; i < 3; i++ {
		talk(t, r1.Endpoint, "incr")
	}
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}

	// A strict home-b finds S, refuses it, and points at home-a.
	b := mk("home-b", artifact.Strict, artifact.Platform{})
	_, code, err = b.Clone(ctx, req)
	var rm *core.RemoteMiss
	if code != core.DeferredFallback || !errors.Is(err, core.ErrIncompatible) || !errors.As(err, &rm) || rm.PreferredHome != "home-a" {
		t.Fatalf("strict B clone = %d %v, want DeferredFallback ErrIncompatible preferring home-a", code, err)
	}
	// Series parity is not enough either: 9.9 is not this kernel's series.
	bs := mk("home-bs", artifact.Parity{Kernel: artifact.ParitySeries}, artifact.Platform{})
	if _, code, err := bs.Clone(ctx, req); code != core.DeferredFallback || !errors.Is(err, core.ErrIncompatible) {
		t.Fatalf("series B clone = %d %v, want DeferredFallback ErrIncompatible", code, err)
	}
	// The tag is still there: nobody claimed it.
	domainRepo := reg + "/deltas/" + strings.TrimPrefix(digest, "sha256:")[:40] + "-" + shortHash(digest)
	if _, found, err := artifact.Resolve(ctx, domainRepo+":"+sessionTag("S"), true); err != nil || !found {
		t.Fatalf("refused session must stay published: found=%v err=%v", found, err)
	}
	// With the kernel check off, home-c takes it and the count is intact.
	c := mk("home-c", artifact.Parity{Kernel: artifact.ParityOff}, artifact.Platform{})
	r2, code, err := c.Clone(ctx, req)
	if err != nil || code != core.OK || r2.Kind != core.ActResume {
		t.Fatalf("relaxed C clone = %v %d %v, want RESUME", err, code, r2.Kind)
	}
	if got := talk(t, r2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on C = %q, want 3", got)
	}
	_, _ = c.Release(ctx, r2.FiberID, true)
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func sessionTag(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "s-" + hex.EncodeToString(sum[:12])
}

func TestTemplateFromRegistryArtifact(t *testing.T) {
	ctx := context.Background()
	// Build the reference zygote into an artifact, with its CRIU images.
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	cfg, _ := artifact.ReadConfig(out)
	if !cfg.HasImages {
		t.Fatal("artifact has no images")
	}
	if _, err := os.Stat(filepath.Join(artifact.ImagesDir(out), "inventory.img")); err != nil {
		t.Fatalf("zygote images missing: %v", err)
	}
	t.Logf("artifact %s kernel=%s libc=%s", digest, cfg.Kernel, cfg.Libc)

	// Push to an in-process registry, then let the runtime pull it by the
	// grant's template digest.
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatalf("push: %v", err)
	}
	cache := t.TempDir()
	rt, err := newHost(host.Config{
		Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: cache,
		CgroupRoot: filepath.Join(cgRoot, "t"+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		RunDir:     filepath.Join("/tmp", "fz-art"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
	}()
	g := core.Grant{UID: "g7", TemplateDigest: digest}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare from registry: %v", err)
	}
	pulled := filepath.Join(cache, strings.TrimPrefix(digest, "sha256:"))
	if _, err := os.Stat(artifact.ZygotePath(pulled)); err != nil {
		t.Fatalf("template not in cache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.ImagesDir(pulled), "inventory.img")); err != nil {
		t.Fatalf("images not unpacked in cache: %v", err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g7", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	_ = rt.Release(ctx, h.ID, false)

	// An unknown digest with no registry entry is refused, not defaulted.
	bogus := core.Grant{UID: "g8", TemplateDigest: "sha256:" + strings.Repeat("1", 64)}
	if err := rt.PrepareTemplate(ctx, bogus); err == nil {
		t.Fatal("unknown digest prepared")
	}
}

func TestCeilingAndPressureSource(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g4", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 8 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	src, ok := rt.(core.PressureSource)
	if !ok {
		t.Fatal("proc runtime must be a PressureSource")
	}
	psi, err := src.Pressure("g4")
	if err != nil {
		t.Fatalf("pressure: %v", err)
	}
	t.Logf("grant PSI some avg10 = %.2f%%", psi)
	// The block ceiling landed on the grant cgroup: memory.high is at
	// least fibers.max * w_budget.
	// Only this process's runtimes count, because earlier runs may have
	// left theirs.
	matches, _ := filepath.Glob(filepath.Join(cgRoot, fmt.Sprintf("t%d-*", os.Getpid()), "g4", "memory.high"))
	if len(matches) != 1 {
		t.Fatalf("grant cgroup memory.high not found: %v", matches)
	}
	b, _ := os.ReadFile(matches[0])
	var high uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &high); err != nil || high < 4*(8<<20) {
		t.Fatalf("memory.high = %q, want >= %d", strings.TrimSpace(string(b)), 4*(8<<20))
	}
	t.Logf("grant ceiling memory.high = %d MiB", high>>20)
}

func TestOverBudgetIsOOMKilled(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:ref", WBudgetBytes: 4 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second,
		Payload: []byte(`{"dirty_bytes": 16777216}`)})
	if err != nil {
		t.Fatalf("clone should succeed (ready is reported before the fiber grows): %v", err)
	}
	select {
	case ex := <-rt.Exits():
		if ex.FiberID != h.ID || ex.Reason != "oom" {
			t.Fatalf("exit = %+v, want oom for %s", ex, h.ID)
		}
		t.Logf("kernel killed it: %s", ex.Detail)
	case <-time.After(10 * time.Second):
		t.Fatal("no exit reported for the over-budget fiber")
	}
	if _, err := rt.Stats(ctx, h.ID); err == nil {
		t.Fatal("stats on a dead fiber must fail")
	}
}

func TestDeadlineIsEnforced(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g3", TemplateDigest: "sha256:ref"}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: "g3", Epoch: 1, Seq: 1}
	dctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	_, err := rt.Clone(dctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 300 * time.Millisecond,
		Payload: []byte(`{"ready_delay_ms": 2000}`)})
	if err == nil {
		t.Fatal("late fiber was delivered")
	}
	t.Logf("late fiber refused: %v", err)
	time.Sleep(200 * time.Millisecond)
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("late fiber left running: %+v", list)
	}
}

// TestResumedDeltaRetiredAndDiscarded follows one named session on one
// home with a delta registry through park, resume, park, resume and a
// discarding release. The resume withdraws the copy the park published,
// so nothing can claim or fall back to that older state. The delta it
// came from stays on disk until the next park supersedes it or the
// release discards it. After the release a Clone creates fresh. The
// steps run in order against one agent.
func TestResumedDeltaRetiredAndDiscarded(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	g := core.Grant{UID: "ret-a", Audience: "home-a", TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 32 << 20,
		LeaseExpiry: time.Now().Add(time.Hour), Policy: core.Policy{Isolation: core.Trusted}}
	rt, err := newHost(host.Config{
		Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
		DeltaRegistry: reg + "/deltas", DeltaKeys: deltaKeys, HomeID: "home-a",
		CgroupRoot: filepath.Join(cgRoot, "ret"+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		RunDir:     filepath.Join("/tmp", "fz-ret-a"), DeltaDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
	})
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	a := &core.Agent{NodeID: "home-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
		Runtime: rt, Verify: tokenVerifier{"g": g}, Health: core.NewSourceHealth(time.Minute, time.Now())}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}
	tag := reg + "/deltas/" + strings.TrimPrefix(digest, "sha256:")[:40] + "-" + shortHash(digest) + ":" + sessionTag("S")
	published := func(t *testing.T) bool {
		t.Helper()
		_, found, err := artifact.Resolve(ctx, tag, true)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	onDisk := func(ref string) bool {
		_, err := os.Stat(filepath.Join(ref, "manifest.json"))
		return err == nil
	}
	parkedRef := func(t *testing.T) string {
		t.Helper()
		st, ref, ok := a.Ledger.SessionState(g.UID, "S")
		if !ok || st != core.StateParked || ref == "" {
			t.Fatalf("S = %v %q %v, want parked with a delta", st, ref, ok)
		}
		return ref
	}
	clone := func(t *testing.T, want core.Action) core.CloneResponse {
		t.Helper()
		r, code, err := a.Clone(ctx, req)
		if err != nil || code != core.OK || r.Kind != want {
			t.Fatalf("clone: %v %d %v, want %v", err, code, r.Kind, want)
		}
		return r
	}
	var fiber, ref1, ref2 string
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"create and count to 3", func(t *testing.T) {
			r := clone(t, core.ActCreate)
			fiber = r.FiberID
			for i := 0; i < 3; i++ {
				talk(t, r.Endpoint, "incr")
			}
		}},
		{"park publishes the delta", func(t *testing.T) {
			if _, code, err := a.Park(ctx, fiber, true); err != nil || code != core.OK {
				t.Fatalf("park: %v %d", err, code)
			}
			ref1 = parkedRef(t)
			if !onDisk(ref1) || !published(t) {
				t.Fatalf("after park: delta on disk %v, published %v", onDisk(ref1), published(t))
			}
		}},
		{"resume keeps the state, withdraws the published copy and keeps the delta on disk", func(t *testing.T) {
			r := clone(t, core.ActResume)
			fiber = r.FiberID
			if got := talk(t, r.Endpoint, "get"); got != "3" {
				t.Fatalf("counter after resume = %q, want 3", got)
			}
			if published(t) {
				t.Fatal("the published copy survived the local resume")
			}
			if !onDisk(ref1) {
				t.Fatal("the delta the fiber came from must stay until the next park or a discard")
			}
		}},
		{"the next park supersedes that delta", func(t *testing.T) {
			if _, code, err := a.Park(ctx, fiber, false); err != nil || code != core.OK {
				t.Fatalf("second park: %v %d", err, code)
			}
			ref2 = parkedRef(t)
			if ref2 == ref1 || !onDisk(ref2) || !published(t) {
				t.Fatalf("after the second park: ref %s (first %s), on disk %v, published %v", ref2, ref1, onDisk(ref2), published(t))
			}
			if onDisk(ref1) {
				t.Fatalf("the superseded delta %s is still on disk", ref1)
			}
		}},
		{"resume again, then release with discard", func(t *testing.T) {
			r := clone(t, core.ActResume)
			if got := talk(t, r.Endpoint, "incr"); got != "4" {
				t.Fatalf("incr after the second resume = %q, want 4", got)
			}
			if code, err := a.Release(ctx, r.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("release: %v %d", err, code)
			}
			if onDisk(ref2) || published(t) {
				t.Fatalf("after the discarding release: delta on disk %v, published %v", onDisk(ref2), published(t))
			}
		}},
		{"a clone after the release creates fresh", func(t *testing.T) {
			r := clone(t, core.ActCreate)
			if got := talk(t, r.Endpoint, "get"); got != "0" {
				t.Fatalf("counter of the fresh session = %q, want 0", got)
			}
			if code, err := a.Release(ctx, r.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("release: %v %d", err, code)
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}
