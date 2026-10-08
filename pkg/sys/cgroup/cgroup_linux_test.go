//go:build linux

package cgroup_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// TestHelperProcess is the body of the processes the tests below start
// in cgroup leaves. It does nothing unless FIBERD_CGROUP_HELPER names a
// role.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("FIBERD_CGROUP_HELPER") == "hog" {
		// Touch far more memory than the leaf allows, until killed.
		for {
			b := make([]byte, 64<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
		}
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// delegatedRoot is the cgroup subtree the dev container delegates to
// the tests, and skips the test without one.
func delegatedRoot(t *testing.T) cgroup.Dir {
	t.Helper()
	root := os.Getenv("FIBERD_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/fiberd"
	}
	f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no writable delegated cgroup root at %s: %v", root, err)
	}
	_ = f.Close()
	return cgroup.Root(root)
}

// testLeaf is a fresh cgroup under the delegated root, named for the
// test, killed and removed with everything under it when the test ends.
func testLeaf(t *testing.T) cgroup.Dir {
	t.Helper()
	name := "test-" + strconv.Itoa(os.Getpid()) + "-" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	d := delegatedRoot(t).Child(name)
	if err := os.Mkdir(d.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Kill()
		waitFor(t, "the test cgroup to be removed", 10*time.Second, func() bool {
			subs, _ := d.Children("")
			for _, s := range subs {
				_ = s.Remove()
			}
			return d.Remove() == nil
		})
	})
	return d
}

// startIn starts the command inside the leaf through clone3, the way
// the runtime places fibers, and reaps it when the test ends.
func startIn(t *testing.T, d cgroup.Dir, cmd *exec.Cmd) *exec.Cmd {
	t.Helper()
	f, err := d.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// TestLeafLifecycle checks that on a real cgroup the settings land in the
// kernel's files, a process placed in the leaf is listed and charged,
// the counters read, Kill ends it and Remove takes the leaf away.
func TestLeafLifecycle(t *testing.T) {
	cases := []struct {
		name          string
		memMax        uint64
		oomGroup      bool
		high, ceiling uint64
		min, pids     uint64
	}{
		{name: "every setting", memMax: 256 << 20, oomGroup: true, high: 128 << 20, ceiling: 192 << 20, min: 1 << 20, pids: 64},
		{name: "no limits", pids: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := testLeaf(t)
			if err := parent.Ensure("memory", "pids"); err != nil {
				t.Fatal(err)
			}
			if got := fileIn(t, parent, "cgroup.subtree_control"); !strings.Contains(got, "memory") || !strings.Contains(got, "pids") {
				t.Fatalf("subtree_control = %q, want memory and pids enabled", got)
			}
			leaf := parent.Child("fiber-1")
			if err := leaf.Create(tc.memMax, tc.oomGroup); err != nil {
				t.Fatal(err)
			}
			if !leaf.Exists() {
				t.Fatal("Create did not make the leaf")
			}
			if tc.memMax > 0 {
				if got := strings.TrimSpace(fileIn(t, leaf, "memory.max")); got != strconv.FormatUint(tc.memMax, 10) {
					t.Fatalf("memory.max = %q, want %d", got, tc.memMax)
				}
				if got := strings.TrimSpace(fileIn(t, leaf, "memory.swap.max")); got != "0" {
					t.Fatalf("memory.swap.max = %q, want 0", got)
				}
			} else if got := strings.TrimSpace(fileIn(t, leaf, "memory.max")); got != "max" {
				t.Fatalf("memory.max = %q, want max", got)
			}
			if got, want := strings.TrimSpace(fileIn(t, leaf, "memory.oom.group")), map[bool]string{true: "1", false: "0"}[tc.oomGroup]; got != want {
				t.Fatalf("memory.oom.group = %q, want %q", got, want)
			}
			if tc.high > 0 {
				if err := leaf.SetCeiling(tc.high, tc.ceiling); err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(fileIn(t, leaf, "memory.high")); got != strconv.FormatUint(tc.high, 10) {
					t.Fatalf("memory.high = %q, want %d", got, tc.high)
				}
				if got := strings.TrimSpace(fileIn(t, leaf, "memory.max")); got != strconv.FormatUint(tc.ceiling, 10) {
					t.Fatalf("memory.max = %q, want %d", got, tc.ceiling)
				}
				if err := leaf.SetMemoryMin(tc.min); err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(fileIn(t, leaf, "memory.min")); got != strconv.FormatUint(tc.min, 10) {
					t.Fatalf("memory.min = %q, want %d", got, tc.min)
				}
			}
			if err := leaf.SetPidsMax(tc.pids); err != nil {
				t.Fatal(err)
			}
			wantPids := "max"
			if tc.pids > 0 {
				wantPids = strconv.FormatUint(tc.pids, 10)
			}
			if got := strings.TrimSpace(fileIn(t, leaf, "pids.max")); got != wantPids {
				t.Fatalf("pids.max = %q, want %q", got, wantPids)
			}

			cmd := startIn(t, leaf, exec.Command("sleep", "60"))
			procs, err := leaf.Procs()
			if err != nil || !slices.Contains(procs, cmd.Process.Pid) {
				t.Fatalf("Procs = %v, %v, want it to hold %d", procs, err, cmd.Process.Pid)
			}
			if cur, err := leaf.MemoryCurrent(); err != nil || cur == 0 {
				t.Fatalf("MemoryCurrent = %d, %v, want a running process's charge", cur, err)
			}
			if anon, err := leaf.Stat("anon"); err != nil {
				t.Fatalf("Stat(anon) = %d, %v", anon, err)
			}
			if _, err := leaf.Stat("no-such-counter"); err == nil || !strings.Contains(err.Error(), "no \"no-such-counter\"") {
				t.Fatalf("Stat(no-such-counter) = %v, want the missing-key error", err)
			}
			if kills, err := leaf.OOMKills(); err != nil || kills != 0 {
				t.Fatalf("OOMKills = %d, %v, want 0", kills, err)
			}
			if hits, err := leaf.PidsMaxHits(); err != nil || hits != 0 {
				t.Fatalf("PidsMaxHits = %d, %v, want 0", hits, err)
			}
			if psi, err := leaf.PSI(); err != nil || psi.SomeAvg10 < 0 || psi.FullAvg10 < 0 {
				t.Fatalf("PSI = %+v, %v, want readable pressure", psi, err)
			}
			kids, err := parent.Children("fiber-")
			if err != nil || len(kids) != 1 || kids[0].Path != leaf.Path {
				t.Fatalf("Children = %v, %v, want the one leaf", kids, err)
			}

			if err := leaf.Kill(); err != nil {
				t.Fatal(err)
			}
			werr := cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(werr, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("the process ended with %v, want SIGKILL", werr)
			}
			if procs, err := leaf.Procs(); err != nil || len(procs) != 0 {
				t.Fatalf("Procs after Kill = %v, %v, want none", procs, err)
			}
			waitFor(t, "the emptied leaf to be removable", 10*time.Second, func() bool { return leaf.Remove() == nil })
			if leaf.Exists() {
				t.Fatal("the leaf is still there after Remove")
			}
		})
	}
}

// TestGroupOOM checks that a leaf over its ceiling is killed as a whole and the
// kill is counted, which is what a parked fiber's ladder reads.
func TestGroupOOM(t *testing.T) {
	cases := []struct {
		name   string
		memMax uint64
	}{
		{name: "a 16 MiB ceiling", memMax: 16 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := testLeaf(t)
			if err := parent.Ensure("memory"); err != nil {
				t.Fatal(err)
			}
			leaf := parent.Child("hog")
			if err := leaf.Create(tc.memMax, true); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
			cmd.Env = append(os.Environ(), "FIBERD_CGROUP_HELPER=hog")
			startIn(t, leaf, cmd)
			werr := cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(werr, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("the hog ended with %v, want SIGKILL from the kernel", werr)
			}
			waitFor(t, "the OOM kill to be counted", 10*time.Second, func() bool {
				kills, err := leaf.OOMKills()
				return err == nil && kills >= 1
			})
			if cur, err := leaf.MemoryCurrent(); err != nil || cur > tc.memMax {
				t.Fatalf("MemoryCurrent = %d, %v, want at most the ceiling %d", cur, err, tc.memMax)
			}
		})
	}
}

// TestPidsMaxRefusesForks checks that with pids.max at one, the one process
// in the leaf cannot fork, and the refusal is counted.
func TestPidsMaxRefusesForks(t *testing.T) {
	cases := []struct {
		name string
		max  uint64
	}{
		{name: "one task", max: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := testLeaf(t)
			if err := parent.Ensure("memory", "pids"); err != nil {
				t.Fatal(err)
			}
			leaf := parent.Child("forker")
			if err := leaf.Create(0, false); err != nil {
				t.Fatal(err)
			}
			if err := leaf.SetPidsMax(tc.max); err != nil {
				t.Fatal(err)
			}
			cmd := startIn(t, leaf, exec.Command("sh", "-c", "true & wait"))
			_ = cmd.Wait()
			hits, err := leaf.PidsMaxHits()
			if err != nil || hits != 1 {
				t.Fatalf("PidsMaxHits = %d, %v, want 1 refused fork", hits, err)
			}
		})
	}
}

// TestDelegateOnARealCgroup checks that a cgroup with a process and no
// controllers enabled gets the process moved into the agent leaf and memory
// and pids enabled below it. Doing it again changes nothing. A cgroup that
// may have no children cannot take the agent leaf, and says so.
func TestDelegateOnARealCgroup(t *testing.T) {
	cases := []struct {
		name           string
		controllers    []string
		maxDescendants string // written to cgroup.max.descendants first
		wantControl    []string
		wantErr        string
	}{
		{name: "the defaults", wantControl: []string{"memory", "pids"}},
		{name: "memory alone", controllers: []string{"memory"}, wantControl: []string{"memory"}},
		{name: "no children allowed", maxDescendants: "0", wantErr: "cgroup: agent leaf: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := testLeaf(t)
			if tc.maxDescendants != "" {
				if err := os.WriteFile(filepath.Join(root.Path, "cgroup.max.descendants"), []byte(tc.maxDescendants), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := startIn(t, root, exec.Command("sleep", "60"))
			sub, err := cgroup.Delegate(root, tc.controllers...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, syscall.EAGAIN) {
					t.Fatalf("Delegate = %v, want EAGAIN as %q", err, tc.wantErr)
				}
				if procs, perr := root.Procs(); perr != nil || !slices.Equal(procs, []int{cmd.Process.Pid}) {
					t.Fatalf("root holds %v, %v, want the process left where it was", procs, perr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sub.Path != root.Child("fiberd").Path {
				t.Fatalf("Delegate = %s, want %s", sub.Path, root.Child("fiberd").Path)
			}
			procs, err := root.Child("agent").Procs()
			if err != nil || !slices.Equal(procs, []int{cmd.Process.Pid}) {
				t.Fatalf("agent leaf holds %v, %v, want the moved process %d", procs, err, cmd.Process.Pid)
			}
			if procs, err := root.Procs(); err != nil || len(procs) != 0 {
				t.Fatalf("root still holds %v, %v", procs, err)
			}
			if got := strings.Fields(fileIn(t, root, "cgroup.subtree_control")); !slices.Equal(got, tc.wantControl) {
				t.Fatalf("subtree_control = %v, want %v", got, tc.wantControl)
			}
			if err := sub.Ensure(tc.wantControl...); err != nil {
				t.Fatalf("Ensure on the delegated subtree: %v", err)
			}
			if _, err := cgroup.Delegate(root, tc.controllers...); err != nil {
				t.Fatalf("a second Delegate: %v", err)
			}
			if got := strings.Fields(fileIn(t, root, "cgroup.subtree_control")); !slices.Equal(got, tc.wantControl) {
				t.Fatalf("subtree_control after a second Delegate = %v, want %v", got, tc.wantControl)
			}
		})
	}
}
