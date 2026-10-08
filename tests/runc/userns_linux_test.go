//go:build linux

package runctest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/caps"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

// home is one runc runtime with the directories it was opened on.
type home struct {
	rt       core.Runtime
	be       backend.Backend
	cgRoot   string
	stateDir string
	runDir   string
}

// newHome opens a runc runtime of its own. mod, when set, adjusts the
// backend options and the host config before they are used.
func newHome(t *testing.T, mod func(*runcbackend.Options, *host.Config)) *home {
	t.Helper()
	name := fmt.Sprintf("rc%d", time.Now().UnixNano()%1_000_000)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ro := runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)}
	hc := host.Config{
		Templates:  map[string]string{"default": "/bin/refzygote --heap-mb 32"},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   filepath.Join(work, name, "deltas"),
		// Routes handoff fibers without listening. Tests hand them
		// connections through Deliver.
		Handoff:    &handoff.Router{},
		HandoffKey: key,
	}
	if mod != nil {
		mod(&ro, &hc)
	}
	be, err := runcbackend.New(ro)
	if err != nil {
		t.Fatal(err)
	}
	hc.Backend = be
	rt, err := host.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	return &home{rt: rt, be: be, cgRoot: hc.CgroupRoot, stateDir: ro.StateDir, runDir: hc.RunDir}
}

// mappedRoot is the host uid the grant's root runs as.
func (h *home) mappedRoot(t *testing.T, grant string) int {
	t.Helper()
	uid, err := h.be.(backend.IDMapper).MappedRoot(grant)
	if err != nil {
		t.Fatal(err)
	}
	return int(uid)
}

// leaf is the fiber's cgroup directory.
func (h *home) leaf(f core.Fence) string {
	return filepath.Join(h.cgRoot, f.GrantUID, fmt.Sprintf("f-%d-%d", f.Epoch, f.Seq))
}

// fiberPID is the fiber's root process as the host sees it, found in its
// leaf. A resumed fiber shares the leaf with the criu that restored it,
// which is told apart by name.
func (h *home) fiberPID(t *testing.T, f core.Fence) int {
	t.Helper()
	procs, err := os.ReadFile(filepath.Join(h.leaf(f), "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Fields(string(procs)) {
		comm, err := os.ReadFile("/proc/" + p + "/comm")
		if err == nil && strings.TrimSpace(string(comm)) != "criu" {
			n, _ := strconv.Atoi(p)
			return n
		}
	}
	t.Fatalf("no fiber in %s: %q", h.leaf(f), procs)
	return 0
}

// fields joins a reply's fields with single spaces, as the kernel pads
// uid_map columns.
func fields(s string) string { return strings.Join(strings.Fields(s), " ") }

// zygotePID is the grant's zygote, the container's init.
func (h *home) zygotePID(t *testing.T, grant string) int {
	t.Helper()
	procs, err := os.ReadFile(filepath.Join(h.cgRoot, grant, "zygote", "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(procs))
	if len(f) == 0 {
		t.Fatalf("no zygote in %s", grant)
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

// statusField reads one key of /proc/<pid>/status.
func statusField(t *testing.T, pid int, key string) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %s in the status of %d", key, pid)
	return ""
}

// nsOf is the namespace link of pid, such as "net:[4026531840]".
func nsOf(t *testing.T, pid int, ns string) string {
	t.Helper()
	l, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// hasCap reports whether a CapEff mask holds the capability.
func hasCap(mask string, c int) bool {
	v, err := strconv.ParseUint(mask, 16, 64)
	return err == nil && v&(1<<uint(c)) != 0
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

// handOff connects to a handoff fiber the way the agent does. One end of
// a fresh pair goes to the fiber, the other is the caller's TLS client.
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

// parkResume parks h and resumes it under the next fence.
func parkResume(t *testing.T, rt core.Runtime, g core.Grant, h core.FiberHandle, seq uint64) core.FiberHandle {
	t.Helper()
	ctx := context.Background()
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
		Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	return h2
}

// TestFiberIsolation pins that the zygote and its fibers run as the
// grant's mapped root, an unprivileged host uid, in namespaces of their
// own. The kernel refuses them host sysctls by identity, they cannot mount
// the cgroup hierarchy or make a user namespace, and their loopback is not
// the host's. Each probe repeats after a park and resume, because a
// restore rebuilds the namespaces.
func TestFiberIsolation(t *testing.T) {
	hm := newHome(t, nil)
	ctx := context.Background()
	g := core.Grant{UID: "iso", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	other := core.Grant{UID: "other", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	for _, gr := range []core.Grant{g, other} {
		if err := hm.rt.PrepareTemplate(ctx, gr); err != nil {
			t.Fatal(err)
		}
	}
	// A listener on the host's loopback stands in for the agent's gRPC
	// port. The test itself reaches it, so a fiber that could would say ok.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if c, err := net.Dial("tcp", ln.Addr().String()); err != nil {
		t.Fatalf("the host listener is not reachable from the host: %v", err)
	} else {
		_ = c.Close()
	}
	hostLn := ln.Addr().String()
	start := hm.mappedRoot(t, g.UID)

	h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	probes := []struct {
		name string
		cmd  string
		want []string // any of these
	}{
		{name: "root inside maps to the grant's range", cmd: "read /proc/self/uid_map", want: []string{fmt.Sprintf("0 %d 65536", start)}},
		{name: "core_pattern refused by identity", cmd: "wopen /proc/sys/kernel/core_pattern", want: []string{"EACCES"}},
		{name: "modprobe refused by identity", cmd: "wopen /proc/sys/kernel/modprobe", want: []string{"EACCES"}},
		{name: "sysrq-trigger refused by identity", cmd: "wopen /proc/sysrq-trigger", want: []string{"EACCES"}},
		{name: "sysfs knob", cmd: "wopen /sys/kernel/mm/transparent_hugepage/enabled", want: []string{"EACCES", "EROFS"}},
		// /sys is a bind of the agent's read-only bind of the host's sysfs,
		// so its flags are locked and the mapped root cannot lift them,
		// and the agent's network devices are there, read-only.
		{name: "sysfs read-only flag locked", cmd: "remount /sys", want: []string{"EPERM"}},
		{name: "the agent's loopback device, read-only", cmd: "wopen /sys/class/net/lo/mtu", want: []string{"EACCES", "EROFS"}},
		{name: "no cgroup hierarchy", cmd: "wopen /sys/fs/cgroup/cgroup.procs", want: []string{"ENOENT"}},
		{name: "cannot mount the cgroup hierarchy", cmd: "mount cgroup2", want: []string{"EPERM"}},
		{name: "cannot make a user namespace", cmd: "unshare user", want: []string{"EPERM"}},
		{name: "host loopback unreachable, loopback up", cmd: "connect " + hostLn, want: []string{"ECONNREFUSED"}},
		{name: "own run directory present", cmd: "stat /host", want: []string{"dir"}},
		{name: "other grant's run directory absent", cmd: "stat " + filepath.Join(hm.runDir, other.UID), want: []string{"ENOENT"}},
		{name: "zygote environment scrubbed", cmd: "getenv FIBERD_CTL_REBIND", want: []string{"-"}},
	}
	hostNet, hostUser := nsOf(t, os.Getpid(), "net"), nsOf(t, os.Getpid(), "user")
	check := func(when string, h core.FiberHandle, fence core.Fence) {
		for _, p := range probes {
			t.Run(when+"/"+p.name, func(t *testing.T) {
				got := fields(talk(t, h.Endpoint, p.cmd))
				for _, w := range p.want {
					if got == w {
						return
					}
				}
				t.Errorf("%s = %q, want one of %v", p.cmd, got, p.want)
			})
		}
		t.Run(when+"/host view", func(t *testing.T) {
			pid := hm.fiberPID(t, fence)
			if uid := strings.Fields(statusField(t, pid, "Uid")); len(uid) == 0 || uid[0] != strconv.Itoa(start) {
				t.Errorf("fiber uid on the host = %v, want %d", uid, start)
			}
			if nsOf(t, pid, "net") == hostNet {
				t.Errorf("fiber is in the host's network namespace")
			}
			if nsOf(t, pid, "user") == hostUser {
				t.Errorf("fiber is in the host's user namespace")
			}
			if hasCap(statusField(t, pid, "CapEff"), caps.SysResource) {
				t.Errorf("fiber holds CAP_SYS_RESOURCE, could raise user.max_user_namespaces")
			}
		})
	}
	check("born", h, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1})
	zpid := hm.zygotePID(t, g.UID)
	if hasCap(statusField(t, zpid, "CapEff"), caps.SysResource) {
		t.Errorf("zygote still holds CAP_SYS_RESOURCE after capping nested user namespaces")
	}
	h2 := parkResume(t, hm.rt, g, h, 2)
	check("resumed", h2, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2})
	_ = hm.rt.Release(ctx, h2.ID, true)
}

// TestCgroupDelegationIsProcsOnly pins that, in the grant's cgroup and
// each fiber leaf, the mapped root owns only cgroup.procs, which clone3
// into the leaf checks. Writability is asked as that uid with access(2),
// which applies the kernel's write checks and changes nothing.
func TestCgroupDelegationIsProcsOnly(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not installed")
	}
	hm := newHome(t, nil)
	ctx := context.Background()
	g := core.Grant{UID: "cg", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
	h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hm.rt.Release(ctx, h.ID, true) }()
	start := hm.mappedRoot(t, g.UID)
	grantCG := filepath.Join(hm.cgRoot, g.UID)
	cases := []struct {
		name     string
		path     string
		wantUID  int
		writable bool // by the mapped root
	}{
		{name: "grant cgroup.procs", path: filepath.Join(grantCG, "cgroup.procs"), wantUID: start, writable: true},
		{name: "leaf cgroup.procs", path: filepath.Join(hm.leaf(fence), "cgroup.procs"), wantUID: start, writable: true},
		{name: "grant directory", path: grantCG, wantUID: 0},
		{name: "grant memory.high", path: filepath.Join(grantCG, "memory.high"), wantUID: 0},
		{name: "grant pids.max", path: filepath.Join(grantCG, "pids.max"), wantUID: 0},
		{name: "grant subtree_control", path: filepath.Join(grantCG, "cgroup.subtree_control"), wantUID: 0},
		{name: "leaf directory", path: hm.leaf(fence), wantUID: 0},
		{name: "leaf memory.max", path: filepath.Join(hm.leaf(fence), "memory.max"), wantUID: 0},
		{name: "leaf pids.max", path: filepath.Join(hm.leaf(fence), "pids.max"), wantUID: 0},
		{name: "leaf cgroup.kill", path: filepath.Join(hm.leaf(fence), "cgroup.kill"), wantUID: 0},
		{name: "zygote cgroup.procs", path: filepath.Join(grantCG, "zygote", "cgroup.procs"), wantUID: 0},
		{name: "root cgroup.procs", path: filepath.Join(hm.cgRoot, "cgroup.procs"), wantUID: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if uid := int(st.Sys().(*syscall.Stat_t).Uid); uid != tc.wantUID {
				t.Errorf("owner = %d, want %d", uid, tc.wantUID)
			}
			u := strconv.Itoa(start)
			err = exec.Command("setpriv", "--reuid", u, "--regid", u, "--clear-groups", "--", "test", "-w", tc.path).Run()
			if writable := err == nil; writable != tc.writable {
				t.Errorf("writable by uid %d = %v, want %v", start, writable, tc.writable)
			}
		})
	}
}

// TestEndpointFamilies pins that fibers serve unix sockets under the run
// directory and handed-off connections, both across park and resume. A
// tcp family is relayed, decided when the runtime opens, because the
// container's network namespace leads nowhere. relay_linux_test.go has
// the bytes going through.
func TestEndpointFamilies(t *testing.T) {
	caller, callerX5t := callerCert(t)
	cases := []struct {
		name string
		mode core.EndpointMode
		say  func(t *testing.T, rt core.Runtime, h core.FiberHandle, line string) string
	}{
		{name: "unix", mode: core.EndpointDirect, say: func(t *testing.T, _ core.Runtime, h core.FiberHandle, line string) string {
			return talk(t, h.Endpoint, line)
		}},
		{name: "handoff", mode: core.EndpointHandoff, say: func(t *testing.T, rt core.Runtime, h core.FiberHandle, line string) string {
			return talkOver(t, handOff(t, rt, h.ID, caller), line)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hm := newHome(t, nil)
			ctx := context.Background()
			g := core.Grant{UID: "ep-" + tc.name, TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20,
				CallerThumbprint: callerX5t, Policy: core.Policy{EndpointMode: tc.mode}}
			if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.say(t, hm.rt, h, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			tc.say(t, hm.rt, h, "incr")
			tc.say(t, hm.rt, h, "incr")
			h2 := parkResume(t, hm.rt, g, h, 2)
			if got := tc.say(t, hm.rt, h2, "get"); got != "2" {
				t.Fatalf("counter after resume = %q, want 2", got)
			}
			_ = hm.rt.Release(ctx, h2.ID, true)
		})
	}
	t.Run("tcp relayed at open", func(t *testing.T) {
		name := fmt.Sprintf("rc%d", time.Now().UnixNano()%1_000_000)
		be, err := runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)})
		if err != nil {
			t.Fatal(err)
		}
		rt, err := host.New(host.Config{
			Backend:    be,
			Templates:  map[string]string{"default": "/bin/refzygote"},
			CgroupRoot: filepath.Join(cgRoot, name),
			RunDir:     filepath.Join("/tmp", "fz-"+name),
			DeltaDir:   filepath.Join(work, name, "deltas"),
			Endpoints:  fiberendpoint.Policy{Family: fiberendpoint.Inet4, Host: "127.0.0.1"},
		})
		if err != nil {
			t.Fatalf("New = %v, want a relaying home", err)
		}
		defer rt.Close()
		if !rt.Relays() {
			t.Fatal("a runc home under a tcp family must relay")
		}
	})
}

// TestResumeOnSecondHome pins that a fiber parked on one home resumes on
// another with its own state, run directory and root filesystem copy. The
// grant's id range follows from its uid and the pool, so the restored
// namespace maps as the dumped one did.
func TestResumeOnSecondHome(t *testing.T) {
	cases := []struct {
		name string
		pool string
	}{
		{name: "default pool", pool: runcbackend.DefaultPool},
		{name: "another pool, same on both homes", pool: "300000:4000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := runcbackend.ParsePool(tc.pool)
			if err != nil {
				t.Fatal(err)
			}
			mod := func(ro *runcbackend.Options, _ *host.Config) { ro.Pool = pool }
			a, b := newHome(t, mod), newHome(t, mod)
			ctx := context.Background()
			g := core.Grant{UID: "mv", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			for _, hm := range []*home{a, b} {
				if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			if a.mappedRoot(t, g.UID) != b.mappedRoot(t, g.UID) {
				t.Fatalf("homes disagree on the grant's range: %d and %d", a.mappedRoot(t, g.UID), b.mappedRoot(t, g.UID))
			}
			h, err := a.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h.Endpoint, "incr")
			talk(t, h.Endpoint, "incr")
			talk(t, h.Endpoint, "incr")
			ref, err := a.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			h2, err := b.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
				Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume on the second home: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "3" {
				t.Fatalf("counter on the second home = %q, want 3", got)
			}
			if want, got := fmt.Sprintf("0 %d 65536", b.mappedRoot(t, g.UID)), fields(talk(t, h2.Endpoint, "read /proc/self/uid_map")); got != want {
				t.Fatalf("uid_map on the second home = %q, want %q", got, want)
			}
			if !strings.HasPrefix(h2.Endpoint, "unix://"+b.runDir+"/") {
				t.Fatalf("resumed endpoint %s is not under the second home's run directory %s", h2.Endpoint, b.runDir)
			}
			if got := talk(t, h2.Endpoint, "wopen /proc/sys/kernel/core_pattern"); got != "EACCES" {
				t.Fatalf("core_pattern on the second home = %q, want EACCES", got)
			}
			if _, err := os.Stat(filepath.Join(b.stateDir, "rootfs", "w-"+g.UID, "bin", "refzygote")); err != nil {
				t.Fatalf("second home has no root filesystem copy for the grant: %v", err)
			}
			_ = b.rt.Release(ctx, h2.ID, true)
		})
	}
}

// TestRangeCollisionRefused pins that two grants hashing to one slot
// cannot both be admitted on a home. The second is refused before any
// cgroup or container of its exists, and the first keeps running.
func TestRangeCollisionRefused(t *testing.T) {
	cases := []struct {
		name      string
		pool      string
		collision bool
	}{
		{name: "one slot, every grant collides", pool: "100000:1", collision: true},
		{name: "default pool, distinct slots", pool: runcbackend.DefaultPool, collision: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := runcbackend.ParsePool(tc.pool)
			if err != nil {
				t.Fatal(err)
			}
			hm := newHome(t, func(ro *runcbackend.Options, _ *host.Config) { ro.Pool = pool })
			ctx := context.Background()
			g1 := core.Grant{UID: "col1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			g2 := core.Grant{UID: "col2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := hm.rt.PrepareTemplate(ctx, g1); err != nil {
				t.Fatal(err)
			}
			err = hm.rt.PrepareTemplate(ctx, g2)
			if tc.collision != errors.Is(err, runcbackend.ErrRangeCollision) {
				t.Fatalf("PrepareTemplate(%s) = %v, want collision %v", g2.UID, err, tc.collision)
			}
			if _, serr := os.Stat(filepath.Join(hm.cgRoot, g2.UID)); tc.collision && serr == nil {
				t.Fatalf("a cgroup was made for the refused grant %s", g2.UID)
			}
			h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g1, Fence: core.Fence{GrantUID: g1.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
			if err != nil {
				t.Fatalf("the first grant no longer clones: %v", err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			_ = hm.rt.Release(ctx, h.ID, true)
		})
	}
}

// TestWarmOwnership pins who owns what a warm leaves on the host. The root
// filesystem copy and the zygote's files belong to the mapped root, the
// run directory stays root's with the grant's group able to create in it,
// and the copy goes with the warm instance.
func TestWarmOwnership(t *testing.T) {
	hm := newHome(t, nil)
	ctx := context.Background()
	g := core.Grant{UID: "own", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	start := hm.mappedRoot(t, g.UID)
	copyDir := filepath.Join(hm.stateDir, "rootfs", "w-"+g.UID)
	workDir := filepath.Join(hm.runDir, g.UID)
	cases := []struct {
		name     string
		path     string
		wantUID  int
		wantGID  int
		wantMode os.FileMode // 0 for any
	}{
		// The mapped root walks through the state directory to its copy.
		// `runc list` makes it 0700 as a side effect, which would fail
		// every warm with EACCES.
		{name: "state directory searchable", path: hm.stateDir, wantUID: 0, wantGID: 0, wantMode: 0o755},
		{name: "rootfs copy", path: copyDir, wantUID: start, wantGID: start},
		{name: "zygote binary in the copy", path: filepath.Join(copyDir, "bin", "refzygote"), wantUID: start, wantGID: start},
		{name: "run directory", path: workDir, wantUID: 0, wantGID: start, wantMode: 0o775},
		{name: "zygote log", path: filepath.Join(workDir, "zygote.log"), wantUID: 0, wantGID: start, wantMode: 0o664},
		{name: "source rootfs untouched", path: filepath.Join(rootfs, "bin", "refzygote"), wantUID: 0, wantGID: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			sys := st.Sys().(*syscall.Stat_t)
			if int(sys.Uid) != tc.wantUID || int(sys.Gid) != tc.wantGID {
				t.Errorf("owner = %d:%d, want %d:%d", sys.Uid, sys.Gid, tc.wantUID, tc.wantGID)
			}
			if tc.wantMode != 0 && st.Mode().Perm() != tc.wantMode {
				t.Errorf("mode = %o, want %o", st.Mode().Perm(), tc.wantMode)
			}
		})
	}
	t.Run("copy removed with the warm instance", func(t *testing.T) {
		hm.rt.(interface{ Close() }).Close()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(copyDir); errors.Is(err, os.ErrNotExist) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s still there after Close", copyDir)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// TestResumeAfterEngineLoss pins that a parked session resumes whether or
// not the grant's zygote is still up. An engine that dies takes its
// container and root filesystem copy with it, and the resume makes what it
// needs again without racing the removal.
func TestResumeAfterEngineLoss(t *testing.T) {
	cases := []struct {
		name     string
		killWarm bool
	}{
		{name: "zygote up", killWarm: false},
		{name: "zygote killed before the resume", killWarm: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hm := newHome(t, nil)
			ctx := context.Background()
			g := core.Grant{UID: "loss", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h.Endpoint, "incr")
			ref, err := hm.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			if tc.killWarm {
				// As the conformance suite's engine-loss hook does, through
				// the zygote's cgroup.
				if err := os.WriteFile(filepath.Join(hm.cgRoot, g.UID, "zygote", "cgroup.kill"), []byte("1"), 0); err != nil {
					t.Fatal(err)
				}
				copyDir := filepath.Join(hm.stateDir, "rootfs", "w-"+g.UID)
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(copyDir); errors.Is(err, os.ErrNotExist) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("the dead zygote's root filesystem copy %s was not released", copyDir)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			h2, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
				Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("counter after resume = %q, want 1", got)
			}
			if got := talk(t, h2.Endpoint, "wopen /proc/sys/kernel/core_pattern"); got != "EACCES" {
				t.Fatalf("core_pattern after resume = %q, want EACCES", got)
			}
			_ = hm.rt.Release(ctx, h2.ID, true)
		})
	}
}
