package mounts

import (
	"errors"
	"strings"
	"testing"
)

// A call is one Mount the fake saw.
type call struct {
	source, target string
	flags          uintptr
}

// fakeMounter answers ReadOnly and Mount per path and records every
// Mount. A path absent from readOnly is writable.
type fakeMounter struct {
	readOnly map[string]bool
	roErr    map[string]error
	mountErr map[call]error
	calls    []call
}

func (f *fakeMounter) ReadOnly(path string) (bool, error) {
	if err := f.roErr[path]; err != nil {
		return false, err
	}
	return f.readOnly[path], nil
}

func (f *fakeMounter) Mount(source, target, _ string, flags uintptr, _ string) error {
	c := call{source: source, target: target, flags: flags}
	f.calls = append(f.calls, c)
	return f.mountErr[c]
}

const (
	cg  = "/sys/fs/cgroup"
	pid = "/proc/sys/kernel/ns_last_pid"
	msg = "/proc/sys/kernel/msg_next_id"
)

// The calls prepare makes, spelled out so a test reads as the kernel
// sees them.
var remountCgroup = call{target: cg, flags: flagRemount | flagBind | flagNosuid | flagNodev | flagNoexec}

func bind(path string) call    { return call{source: path, target: path, flags: flagBind} }
func remount(path string) call { return call{target: path, flags: flagRemount | flagBind} }

// TestPrepare checks that prepare touches only what is read-only, stops
// at a cgroup failure, and tries every sysctl before reporting the ones
// that failed under ErrSysctlsReadOnly.
func TestPrepare(t *testing.T) {
	errDenied := errors.New("operation not permitted")
	cases := []struct {
		name        string
		readOnly    map[string]bool
		roErr       map[string]error
		mountErr    map[call]error
		wantCalls   []call
		wantErr     error    // the cause, through errors.Is
		wantSysctls bool     // the error wraps ErrSysctlsReadOnly
		wantNamed   []string // paths the error message must name
	}{
		{
			name: "nothing read-only makes no call",
		},
		{
			name:      "a read-only cgroup mount gets one remount",
			readOnly:  map[string]bool{cg: true},
			wantCalls: []call{remountCgroup},
		},
		{
			name:      "read-only sysctls get a bind and a remount each",
			readOnly:  map[string]bool{pid: true, msg: true},
			wantCalls: []call{bind(pid), remount(pid), bind(msg), remount(msg)},
		},
		{
			name:      "the cgroup mount comes before the sysctls",
			readOnly:  map[string]bool{cg: true, pid: true, msg: true},
			wantCalls: []call{remountCgroup, bind(pid), remount(pid), bind(msg), remount(msg)},
		},
		{
			name:      "a cgroup check failure stops everything",
			readOnly:  map[string]bool{pid: true},
			roErr:     map[string]error{cg: errDenied},
			wantErr:   errDenied,
			wantNamed: []string{cg},
		},
		{
			name:      "a cgroup remount failure leaves the sysctls alone",
			readOnly:  map[string]bool{cg: true, pid: true},
			mountErr:  map[call]error{remountCgroup: errDenied},
			wantCalls: []call{remountCgroup},
			wantErr:   errDenied,
			wantNamed: []string{cg},
		},
		{
			name:        "a sysctl bind failure still tries the rest",
			readOnly:    map[string]bool{cg: true, pid: true, msg: true},
			mountErr:    map[call]error{bind(pid): errDenied},
			wantCalls:   []call{remountCgroup, bind(pid), bind(msg), remount(msg)},
			wantErr:     errDenied,
			wantSysctls: true,
			wantNamed:   []string{pid},
		},
		{
			name:        "a sysctl remount failure still tries the rest",
			readOnly:    map[string]bool{pid: true, msg: true},
			mountErr:    map[call]error{remount(pid): errDenied},
			wantCalls:   []call{bind(pid), remount(pid), bind(msg), remount(msg)},
			wantErr:     errDenied,
			wantSysctls: true,
			wantNamed:   []string{pid},
		},
		{
			name:        "a sysctl check failure counts as that file",
			readOnly:    map[string]bool{msg: true},
			roErr:       map[string]error{pid: errDenied},
			wantCalls:   []call{bind(msg), remount(msg)},
			wantErr:     errDenied,
			wantSysctls: true,
			wantNamed:   []string{pid},
		},
		{
			name:        "every failed sysctl is named",
			readOnly:    map[string]bool{pid: true, msg: true},
			mountErr:    map[call]error{bind(pid): errDenied, bind(msg): errDenied},
			wantCalls:   []call{bind(pid), bind(msg)},
			wantErr:     errDenied,
			wantSysctls: true,
			wantNamed:   []string{pid, msg},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &fakeMounter{readOnly: tc.readOnly, roErr: tc.roErr, mountErr: tc.mountErr}
			err := prepare(m, cg, []string{pid, msg})
			if tc.wantErr == nil && err != nil {
				t.Fatalf("prepare = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("prepare = %v, want a wrap of %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrSysctlsReadOnly); got != tc.wantSysctls {
				t.Fatalf("errors.Is(%v, ErrSysctlsReadOnly) = %v, want %v", err, got, tc.wantSysctls)
			}
			for _, path := range tc.wantNamed {
				if !strings.Contains(err.Error(), path) {
					t.Fatalf("error %q does not name %s", err, path)
				}
			}
			if len(m.calls) != len(tc.wantCalls) {
				t.Fatalf("calls = %+v, want %+v", m.calls, tc.wantCalls)
			}
			for i, c := range m.calls {
				if c != tc.wantCalls[i] {
					t.Fatalf("call %d = %+v, want %+v", i, c, tc.wantCalls[i])
				}
				if c.flags&flagRdonly != 0 {
					t.Fatalf("call %d = %+v sets the read-only bit", i, c)
				}
			}
		})
	}
}

// TestCRIUSysctls pins the four kernel files CRIU writes on restore, in
// the order Prepare tries them.
func TestCRIUSysctls(t *testing.T) {
	cases := []struct {
		name string
		at   int
		want string
	}{
		{name: "the next pid", at: 0, want: "/proc/sys/kernel/ns_last_pid"},
		{name: "the next message queue id", at: 1, want: "/proc/sys/kernel/msg_next_id"},
		{name: "the next semaphore id", at: 2, want: "/proc/sys/kernel/sem_next_id"},
		{name: "the next shared memory id", at: 3, want: "/proc/sys/kernel/shm_next_id"},
	}
	if len(CRIUSysctls) != len(cases) {
		t.Fatalf("CRIUSysctls = %v, want %d files", CRIUSysctls, len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CRIUSysctls[tc.at]; got != tc.want {
				t.Fatalf("CRIUSysctls[%d] = %q, want %q", tc.at, got, tc.want)
			}
			if !strings.HasPrefix(tc.want, "/proc/sys/kernel/") {
				t.Fatalf("%q is not a kernel sysctl", tc.want)
			}
		})
	}
}
