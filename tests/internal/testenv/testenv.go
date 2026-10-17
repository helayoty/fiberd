//go:build linux && integration

// Package testenv is what every suite under tests/ sets up the same way.
// That is the delegated cgroup root of the dev container, the hardened
// build of the reference zygote, the rootfs the sandboxed backends run
// it in, and the percentile report the benchmarks print. A helper one
// suite alone needs stays in that suite.
package testenv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"
)

// mntnsEnv marks a test binary already running in a mount namespace of
// its own, so the re-exec happens once.
const mntnsEnv = "FIBERD_TEST_MNTNS"

// OwnMountNamespace re-executes the test binary in a private mount
// namespace, so the restore roots and binds one suite mounts never reach
// the fibers another suite forks beside it. The proc backend binds / at
// /tmp/fiberd-root-<pid> while a runtime is open, and a fiber forked
// meanwhile by another suite's zygote copies that bind into its own
// namespace, where criu records it at park and then cannot restore it
// once the bind is gone. unshare execs in place, so the pid and the
// standard streams go test holds stay the same. Call it first in
// TestMain. Without unshare, or outside the container, the suite goes
// on in the namespace it has.
func OwnMountNamespace() {
	if os.Getenv(mntnsEnv) != "" {
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testenv: no unshare, so this suite shares its mount namespace: %v\n", err)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testenv: own executable: %v\n", err)
		return
	}
	args := append([]string{"unshare", "--mount", "--propagation", "private", exe}, os.Args[1:]...)
	env := append(os.Environ(), mntnsEnv+"=1")
	if err := syscall.Exec(unshare, args, env); err != nil {
		fmt.Fprintf(os.Stderr, "testenv: unshare the mount namespace: %v\n", err)
	}
}

// CgroupRoot is the cgroup subtree the dev container delegates to the
// tests, $FIBERD_CGROUP_ROOT or its default.
func CgroupRoot() string {
	if root := os.Getenv("FIBERD_CGROUP_ROOT"); root != "" {
		return root
	}
	return "/sys/fs/cgroup/fiberd"
}

// WritableCgroupRoot is CgroupRoot once the tests may create leaves
// under it, and otherwise says why they may not.
func WritableCgroupRoot() (string, error) {
	root := CgroupRoot()
	f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("%s not writable (run under make integration-tests)", root)
	}
	_ = f.Close()
	return root, nil
}

// RequireCgroupRoot is WritableCgroupRoot for a TestMain, before anything
// else is set up. A root the tests may not write ends the binary as a
// skip, so a run outside the dev container passes with a line saying why.
func RequireCgroupRoot(suite string) string {
	root, err := WritableCgroupRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping %s tests: %v\n", suite, err)
		os.Exit(0)
	}
	return root
}

// RepoRoot is the checkout this file sits in, so a suite finds the
// zygote sources and the scripts wherever it lives under tests/.
func RepoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("testenv: no caller information")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// ZygoteBuildFlags mirrors ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS in the
// Makefile, so the tests run the zygote hardened as it ships. On arm64
// that includes -mbranch-protection=none, because a restored process
// keeps stale pointer-authentication keys. goarch is runtime.GOARCH.
func ZygoteBuildFlags(goarch string) []string {
	flags := []string{"-D_FORTIFY_SOURCE=3", "-O2", "-fstack-protector-strong", "-fstack-clash-protection", "-fPIE",
		"-Wformat=2", "-Werror=format-security"}
	if goarch == "arm64" {
		flags = append(flags, "-mbranch-protection=none")
	}
	return append(flags, "-pie", "-Wl,-z,relro,-z,now")
}

// CoreArchive builds the zygote library's Rust core
// (sdk/c/template/core) once per test binary and returns the static
// archive every C build of the library links after libfiberzygote.c.
// cargo runs in the crate, so rustup takes the toolchain its
// rust-toolchain.toml pins.
var CoreArchive = sync.OnceValues(func() (string, error) {
	dir := filepath.Join(RepoRoot(), "sdk", "c", "template", "core")
	build := exec.Command("cargo", "build", "--release", "--locked")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build the zygote core: %w: %s", err, out)
	}
	return filepath.Join(dir, "target", "release", "libfiberzygote_core.a"), nil
})

// BuildZygote compiles the reference zygote with TLS for handoff grants
// into dir and returns the binary's path.
func BuildZygote(dir string) (string, error) {
	core, err := CoreArchive()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "refzygote")
	zygote := filepath.Join(RepoRoot(), "sdk", "c", "template")
	args := append(ZygoteBuildFlags(runtime.GOARCH), "-pthread", "-DFZ_TLS", "-o", bin,
		filepath.Join(zygote, "refzygote.c"), filepath.Join(zygote, "libfiberzygote.c"), core, "-lssl", "-lcrypto")
	build := exec.Command("gcc", args...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("build refzygote: %w", err)
	}
	return bin, nil
}

// BuildRootfs builds the rootfs the gvisor and runc backends run the
// reference zygote in (hack/gvisor/rootfs.sh) at dir.
func BuildRootfs(dir string) error {
	return buildRootfs(filepath.Join("hack", "gvisor", "rootfs.sh"), dir)
}

// BuildPythonRootfs builds that rootfs with CPython and the Python SDK in
// it (hack/python/rootfs.sh) at dir, for the Python reference template.
func BuildPythonRootfs(dir string) error {
	return buildRootfs(filepath.Join("hack", "python", "rootfs.sh"), dir)
}

func buildRootfs(script, dir string) error {
	build := exec.Command(filepath.Join(RepoRoot(), script), dir)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build rootfs: %w", err)
	}
	return nil
}

// Report logs the percentiles, maximum and mean of the durations.
func Report(t testing.TB, label string, ds []time.Duration) {
	t.Helper()
	if len(ds) == 0 {
		return
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	pct := func(p float64) time.Duration { return ds[int(float64(len(ds)-1)*p)] }
	t.Logf("%s: p50=%s p90=%s p99=%s max=%s mean=%s", label,
		pct(0.5).Round(10*time.Microsecond), pct(0.9).Round(10*time.Microsecond), pct(0.99).Round(10*time.Microsecond),
		ds[len(ds)-1].Round(10*time.Microsecond), (sum / time.Duration(len(ds))).Round(10*time.Microsecond))
}
