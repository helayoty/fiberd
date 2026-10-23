//go:build linux

package cloudhv

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestCloneMode checks that a Clone restores copy-on-write unless told
// otherwise. Copy was the default before, which the "" case guards
// against.
func TestCloneMode(t *testing.T) {
	cases := []struct {
		name, opt, want string
	}{
		{name: "default", opt: "", want: "copyonwrite"},
		{name: "copy", opt: "copy", want: "copy"},
		{name: "ondemand", opt: "ondemand", want: "ondemand"},
		{name: "copyonwrite", opt: "copyonwrite", want: "copyonwrite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloneMode(tc.opt); got != tc.want {
				t.Fatalf("cloneMode(%q) = %q, want %q", tc.opt, got, tc.want)
			}
		})
	}
}

// TestRestoreArg checks that copy, the VMM's default, goes unnamed and
// every other mode is named.
func TestRestoreArg(t *testing.T) {
	cases := []struct {
		name, mode, want string
	}{
		{name: "copy", mode: "copy", want: "source_url=file://" + vmFrom},
		{name: "ondemand", mode: "ondemand", want: "source_url=file://" + vmFrom + ",memory_restore_mode=ondemand"},
		{name: "copyonwrite", mode: "copyonwrite", want: "source_url=file://" + vmFrom + ",memory_restore_mode=copyonwrite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := restoreArg(tc.mode); got != tc.want {
				t.Fatalf("restoreArg(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

// TestRestoreFootprint checks that a copy whose leaf count could not be
// read still reports the whole guest, and that a count read is kept.
func TestRestoreFootprint(t *testing.T) {
	const whole = 320 << 20
	cases := []struct {
		name string
		read uint64
		mode string
		want uint64
	}{
		{name: "copy read", read: 300 << 20, mode: "copy", want: 300 << 20},
		{name: "copy unread", read: 0, mode: "copy", want: whole},
		{name: "copyonwrite read", read: 70 << 20, mode: "copyonwrite", want: 70 << 20},
		{name: "copyonwrite unread", read: 0, mode: "copyonwrite", want: 0},
		{name: "ondemand unread", read: 0, mode: "ondemand", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := restoreFootprint(tc.read, whole, tc.mode); got != tc.want {
				t.Fatalf("restoreFootprint(%d, %d, %q) = %d, want %d", tc.read, uint64(whole), tc.mode, got, tc.want)
			}
		})
	}
}

// TestMapsFile checks that a maps listing is read by the base name of
// each pathname, whole and exact, wherever the kernel says the file is.
func TestMapsFile(t *testing.T) {
	const others = "00400000-00a00000 r-xp 00000000 00:1f 12                                 /fiberd/vm/bin/vmm\n" +
		"01200000-01400000 rw-p 00000000 00:00 0                                  [heap]\n" +
		"7f0000000000-7f0000100000 rw-p 00000000 00:00 0 \n"
	line := func(path string) string {
		return "7f1000000000-7f1010000000 rw-p 00000000 00:2a 77                         " + path + "\n"
	}
	cases := []struct {
		name, maps, file string
		want             bool
	}{
		{name: "mapped", maps: others + line("/fiberd/vm/from/memory-ranges"), file: "memory-ranges", want: true},
		{name: "host path", maps: others + line("/var/lib/fiberd/warm/0123abcd/memory-ranges"), file: "memory-ranges", want: true},
		{name: "deleted", maps: others + line("/fiberd/vm/from/memory-ranges (deleted)"), file: "memory-ranges", want: true},
		{name: "others only", maps: others, file: "memory-ranges"},
		{name: "longer name", maps: others + line("/fiberd/vm/from/memory-ranges.tmp"), file: "memory-ranges"},
		{name: "directory of that name", maps: others + line("/fiberd/memory-ranges/vmm"), file: "memory-ranges"},
		{name: "bracketed name", maps: others + line("[memory-ranges]"), file: "[memory-ranges]"},
		{name: "space in path", maps: others + line("/fiberd/vm/from/a b"), file: "a b", want: true},
		{name: "space in path, other half", maps: others + line("/fiberd/vm/from/a b"), file: "b"},
		{name: "empty", maps: "", file: "memory-ranges"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapsFile(strings.NewReader(tc.maps), tc.file); got != tc.want {
				t.Fatalf("mapsFile(%q) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

// errStubProbe is what stubStarter's Probe returns. A probe that gets as
// far as it took the restore mode.
var errStubProbe = errors.New("stub probe")

// stubStarter is a starter that never starts anything.
type stubStarter struct{}

func (stubStarter) Version(context.Context) (string, error) { return "", errors.New("stub version") }
func (stubStarter) Probe() error                            { return errStubProbe }
func (stubStarter) Start(jailSpec) (process, error)         { return nil, errors.New("stub start") }

// TestProbeRestoreMode checks which restore modes open the backend.
func TestProbeRestoreMode(t *testing.T) {
	cases := []struct {
		name, mode string
		ok         bool
	}{
		{name: "default", mode: "", ok: true},
		{name: "copy", mode: "copy", ok: true},
		{name: "ondemand", mode: "ondemand", ok: true},
		{name: "copyonwrite", mode: "copyonwrite", ok: true},
		{name: "unknown", mode: "cow"},
		{name: "wrong case", mode: "COPY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBackend(Options{VMM: "vmm", Kernel: "k", Rootfs: "r", StateDir: t.TempDir(), RestoreMode: tc.mode}, stubStarter{})
			err := b.ProbeErr()
			if tc.ok {
				if !errors.Is(err, errStubProbe) {
					t.Fatalf("mode %q: ProbeErr = %v, want the stub's probe error", tc.mode, err)
				}
				return
			}
			if err == nil || errors.Is(err, errStubProbe) || !strings.Contains(err.Error(), "restore mode") {
				t.Fatalf("mode %q: ProbeErr = %v, want a refusal of the restore mode", tc.mode, err)
			}
		})
	}
}
