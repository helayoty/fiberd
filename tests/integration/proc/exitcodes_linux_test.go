//go:build linux && integration

package proctest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

var (
	failChildOnce sync.Once
	failChildBin  string
	failChildErr  error
)

// failChild builds the launcher in testdata/failchild.c once per test
// binary, beside refzygote, and returns its path.
func failChild(t *testing.T) string {
	t.Helper()
	failChildOnce.Do(func() {
		failChildBin = filepath.Join(filepath.Dir(zygoteBin), "failchild")
		build := exec.Command("gcc", "-O2", "-o", failChildBin, "testdata/failchild.c")
		if out, err := build.CombinedOutput(); err != nil {
			failChildErr = fmt.Errorf("%w: %s", err, out)
		}
	})
	if failChildErr != nil {
		t.Skipf("cannot build failchild: %v", failChildErr)
	}
	return failChildBin
}

// needRoot skips a test that must make the namespaces and mounts a
// fiber gets, which takes euid 0 with CAP_SYS_ADMIN.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !hasCap(t, procStatus(t, os.Getpid(), "CapEff"), capSysAdmin) {
		t.Skip("the test lacks CAP_SYS_ADMIN: the fiber's namespaces would be refused")
	}
}

// TestChildExitCodes pins the exit code and the reason fiberd reports
// for each step of a child's setup that can fail, before on_fiber. The
// failchild launcher fails one system call with EPERM in the zygote's
// children alone, so the zygote prepares and serves as usual and only
// the child's step fails. A call is picked by its number and, where the
// child makes it more than once, by the flags that tell its uses apart.
// Exit 113 and 125 are pinned in noclone3_linux_test.go. 116 is retired.
func TestChildExitCodes(t *testing.T) {
	needRoot(t)
	launcher := failChild(t)
	const anyArg = -1 // match on the call's number alone
	cases := []struct {
		name  string
		nr    uintptr
		arg   int    // the argument matched, or anyArg
		value uint32 // its low 32 bits, ANDed with mask, must equal value
		mask  uint32
		want  string
	}{
		{
			// mount_ns's first step, MS_REC|MS_PRIVATE on /.
			name: "110 a private mount namespace refused",
			nr:   unix.SYS_MOUNT, arg: 3, value: unix.MS_REC | unix.MS_PRIVATE, mask: 0xffffffff,
			want: "died before ready: exit:110 (could not make its mount namespace private)",
		},
		{
			// The fresh /proc of its pid namespace. The child makes no
			// other mount with exactly these flags (its covers add MS_RDONLY).
			name: "111 its own /proc refused",
			nr:   unix.SYS_MOUNT, arg: 3, value: unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, mask: 0xffffffff,
			want: "died before ready: exit:111 (could not mount its own /proc)",
		},
		{
			// The plain bind of /proc/sys and the other host controls
			// onto themselves, before their read-only remount.
			name: "115 the read-only host controls refused",
			nr:   unix.SYS_MOUNT, arg: 3, value: unix.MS_BIND, mask: 0xffffffff,
			want: "died before ready: exit:115 (could not make the host controls under /proc read-only)",
		},
		{
			// The child unmounts nothing but the DROP paths.
			name: "112 a DROP path that will not unmount",
			nr:   unix.SYS_UMOUNT2, arg: anyArg,
			want: "died before ready: exit:112 (could not unmount a DROP path)",
		},
		{
			// drop_caps empties its sets with capset, after the mounts.
			name: "114 the capability drop refused",
			nr:   unix.SYS_CAPSET, arg: anyArg,
			want: "died before ready: exit:114 (could not drop its capabilities)",
		},
		{
			// own_pair, the fiber's own channel pair.
			name: "120 its own channel pair refused",
			nr:   unix.SYS_SOCKETPAIR, arg: anyArg,
			want: "died before ready: exit:120 (could not set up its descriptors)",
		},
		{
			// The read of its record off the channel at fd 4.
			name: "121 its incarnation record unreadable",
			nr:   unix.SYS_RECVMSG, arg: 0, value: 4, mask: 0xffffffff,
			want: "died before ready: exit:121 (did not get its incarnation record)",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			grant := fmt.Sprintf("gx%d", i)
			argv := []string{launcher, strconv.FormatUint(uint64(tc.nr), 10), strconv.Itoa(tc.arg),
				fmt.Sprintf("%#x", tc.value), fmt.Sprintf("%#x", tc.mask), zygoteBin, "--heap-mb", "16"}
			be, w := warmArgv(t, dir, grant, argv, nil)
			_, err := cloneDirect(t, be, w, dir, grant+"/1-1", "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("clone = %v, want %q", err, tc.want)
			}
		})
	}
}
