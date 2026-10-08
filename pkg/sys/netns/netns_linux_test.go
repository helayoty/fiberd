//go:build linux

package netns_test

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/netns"
)

// newNetNS starts a process in a network namespace of its own and
// returns its pid. The kernel refusing the namespace skips the test.

// needRoot skips a test that needs root. The launcher chowns into mapped
// id ranges and enters namespaces, so these run in the dev container.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run it with hack/dev/run.sh)")
	}
}
func newNetNS(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("cannot make a network namespace: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// nsInode is the identity of pid's network namespace.
func nsInode(t *testing.T, pid int) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// threadNS is the network namespace of the calling thread.
func threadNS(t *testing.T) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// socketNS is the network namespace a socket was created in, asked of
// the socket itself (SIOCGSKNS).
func socketNS(t *testing.T, fd int) uint64 {
	t.Helper()
	const siocgskns = 0x894c
	nsfd, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocgskns, 0)
	if errno != 0 {
		t.Fatalf("SIOCGSKNS: %v", errno)
	}
	defer func() { _ = syscall.Close(int(nsfd)) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(nsfd), &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// tasksIn reports whether any thread of this process is in the network
// namespace with that identity.
func tasksIn(t *testing.T, ino uint64) bool {
	t.Helper()
	tasks, err := filepath.Glob("/proc/self/task/*/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range tasks {
		var st syscall.Stat_t
		if err := syscall.Stat(link, &st); err == nil && st.Ino == ino {
			return true
		}
	}
	return false
}

// connectLoopback connects a TCP socket to 127.0.0.1 port 1 in the
// calling thread's namespace. Nothing listens there, so the answer is
// ECONNREFUSED when loopback traffic flows and ENETUNREACH while lo is
// down.
func connectLoopback() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(s) }()
	return syscall.Connect(s, &syscall.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}})
}

// TestDo: fn runs on a thread inside the target's network namespace,
// its error comes back, and no thread of ours stays in that namespace
// afterwards. A process that is not there is an error before fn runs.
func TestDo(t *testing.T) {
	errFn := errors.New("from fn")
	child := newNetNS(t)
	cases := []struct {
		name   string
		pid    int
		fnErr  error
		wantIs error
	}{
		{name: "our own namespace", pid: os.Getpid()},
		{name: "fn's error comes back", pid: os.Getpid(), fnErr: errFn, wantIs: errFn},
		{name: "another namespace", pid: child},
		{name: "no such process", pid: math.MaxInt32, wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			var inside uint64
			err := netns.Do(tc.pid, func() error {
				ran = true
				inside = threadNS(t)
				return tc.fnErr
			})
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Do = %v, want %v", err, tc.wantIs)
				}
				if ran != (tc.fnErr != nil) {
					t.Fatalf("fn ran: %v, want %v", ran, tc.fnErr != nil)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := nsInode(t, tc.pid); !ran || inside != want {
				t.Fatalf("fn ran in namespace %d (ran %v), want %d", inside, ran, want)
			}
			if tc.pid != os.Getpid() && tasksIn(t, nsInode(t, tc.pid)) {
				t.Fatal("a thread of ours is still in the target's namespace")
			}
		})
	}
}

// TestSocketpair: the pair is made in the target's namespace, connected
// and close-on-exec.
func TestSocketpair(t *testing.T) {
	child := newNetNS(t)
	cases := []struct {
		name   string
		pid    int
		typ    int
		wantIs error
	}{
		{name: "stream in our namespace", pid: os.Getpid(), typ: syscall.SOCK_STREAM},
		{name: "seqpacket in another namespace", pid: child, typ: syscall.SOCK_SEQPACKET},
		{name: "no such process", pid: math.MaxInt32, typ: syscall.SOCK_STREAM, wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := netns.Socketpair(tc.pid, tc.typ)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) || fds != [2]int{-1, -1} {
					t.Fatalf("Socketpair = %v, %v, want [-1 -1] and %v", fds, err, tc.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Close(fds[0]); _ = syscall.Close(fds[1]) }()
			for _, fd := range fds {
				if flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0); errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
					t.Fatalf("fd %d close-on-exec flags = %#x %v, want FD_CLOEXEC", fd, flags, errno)
				}
				if got, want := socketNS(t, fd), nsInode(t, tc.pid); got != want {
					t.Fatalf("fd %d lives in namespace %d, want %d", fd, got, want)
				}
			}
			if _, err := syscall.Write(fds[0], []byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			if n, err := syscall.Read(fds[1], buf); err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("read %q, %v, want ping", buf[:n], err)
			}
		})
	}
}

// TestLoopbackUp: a fresh namespace has no route to 127.0.0.1 until lo
// is up. One that is up already stays as it is.
func TestLoopbackUp(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name        string
		pid         func(t *testing.T) int
		downAtFirst bool
		wantIs      error
	}{
		{name: "a fresh namespace", pid: newNetNS, downAtFirst: true},
		{name: "our own namespace, already up", pid: func(*testing.T) int { return os.Getpid() }},
		{name: "no such process", pid: func(*testing.T) int { return math.MaxInt32 }, wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid := tc.pid(t)
			if tc.downAtFirst {
				err := netns.Do(pid, connectLoopback)
				if !errors.Is(err, syscall.ENETUNREACH) {
					t.Fatalf("connect to 127.0.0.1 before = %v, want ENETUNREACH", err)
				}
			}
			for i := range 2 {
				err := netns.LoopbackUp(pid)
				if tc.wantIs != nil {
					if !errors.Is(err, tc.wantIs) {
						t.Fatalf("LoopbackUp = %v, want %v", err, tc.wantIs)
					}
					return
				}
				if err != nil {
					t.Fatalf("LoopbackUp call %d = %v", i+1, err)
				}
				if err := netns.Do(pid, connectLoopback); !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("connect to 127.0.0.1 after call %d = %v, want ECONNREFUSED", i+1, err)
				}
			}
		})
	}
}

// TestHelperProcess is the body of the unprivileged processes
// TestWithoutCapabilities starts. It does nothing unless
// FIBERD_NETNS_HELPER names what to try against the namespace of
// FIBERD_NETNS_PID, and fails loudly when the refusal is not the one
// the package promises.
func TestHelperProcess(t *testing.T) {
	what := os.Getenv("FIBERD_NETNS_HELPER")
	if what == "" {
		return
	}
	pid, err := strconv.Atoi(os.Getenv("FIBERD_NETNS_PID"))
	if err != nil {
		t.Fatal(err)
	}
	var want string
	switch what {
	case "enter":
		ran := false
		err = netns.Do(pid, func() error { ran = true; return nil })
		if ran {
			t.Fatal("fn ran although the namespace could not be entered")
		}
		want = fmt.Sprintf("netns: enter the network namespace of %d: ", pid)
	case "loopback":
		err = netns.LoopbackUp(pid)
		want = "netns: bring lo up: "
	}
	if !errors.Is(err, syscall.EPERM) || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("%s = %v, want EPERM as %q", what, err, want)
	}
}

// TestWithoutCapabilities: entering a namespace needs CAP_SYS_ADMIN
// and bringing lo up CAP_NET_ADMIN. A process without them is refused
// with EPERM, and the refusal says which step failed.
func TestWithoutCapabilities(t *testing.T) {
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv not installed")
	}
	cases := []struct {
		name string
		what string
		drop string
	}{
		{name: "no CAP_SYS_ADMIN, no entry", what: "enter", drop: "sys_admin"},
		{name: "no CAP_NET_ADMIN, lo stays down", what: "loopback", drop: "net_admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid := newNetNS(t)
			args := []string{"--bounding-set=-" + tc.drop, os.Args[0], "-test.run=^TestHelperProcess$"}
			if dir := flag.Lookup("test.gocoverdir"); dir != nil && dir.Value.String() != "" {
				// Count the helper's coverage with ours.
				args = append(args, "-test.gocoverdir="+dir.Value.String())
			}
			cmd := exec.Command(setpriv, args...)
			cmd.Env = append(os.Environ(), "FIBERD_NETNS_HELPER="+tc.what, "FIBERD_NETNS_PID="+strconv.Itoa(pid))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("helper without CAP_%s: %v\n%s", strings.ToUpper(tc.drop), err, out)
			}
			if tc.what == "loopback" {
				if err := netns.Do(pid, connectLoopback); !errors.Is(err, syscall.ENETUNREACH) {
					t.Fatalf("connect to 127.0.0.1 after the refused LoopbackUp = %v, want ENETUNREACH (lo still down)", err)
				}
			}
		})
	}
}
