package caps

import (
	"slices"
	"testing"
)

// TestStatusCaps checks that the inheritable and ambient masks come out of a
// /proc/<pid>/status text as the kernel writes them, and the lines that
// are not there (CapAmb on an old kernel) or not well formed are told
// apart.
func TestStatusCaps(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		inh     uint64
		amb     uint64
		wantErr bool
	}{
		{
			name: "full status with empty sets",
			status: "Name:\tfiberd\nUmask:\t0022\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n" +
				"CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n",
		},
		{
			name:   "inheritable and ambient set",
			status: "CapInh:\t0000000000200100\nCapPrm:\t0000000000200100\nCapEff:\t0000000000200100\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000200000\n",
			inh:    1<<SysAdmin | 1<<SetPCAP,
			amb:    1 << SysAdmin,
		},
		{
			name:   "kernel without ambient capabilities",
			status: "CapInh:\t0000000000001000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\n",
			inh:    1 << NetAdmin,
		},
		{
			name:   "unrelated keys with the same prefix are not read",
			status: "CapInhX:\tffffffffffffffff\nCapInh:\t0000000000000001\nCapAmbient:\tffffffffffffffff\n",
			inh:    1,
		},
		{name: "no CapInh line", status: "Name:\tfiberd\nCapPrm:\t0\n", wantErr: true},
		{name: "mask is not hex", status: "CapInh:\tnone\n", wantErr: true},
		{name: "empty", status: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inh, amb, err := statusCaps(tc.status)
			if (err != nil) != tc.wantErr {
				t.Fatalf("statusCaps: err = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if inh != tc.inh || amb != tc.amb {
				t.Fatalf("statusCaps = inh %#x amb %#x, want inh %#x amb %#x", inh, amb, tc.inh, tc.amb)
			}
		})
	}
}

// TestOutside checks what a mask holds beyond keep, ascending, and
// nothing when it holds only keep.
func TestOutside(t *testing.T) {
	cases := []struct {
		name string
		mask uint64
		keep []int
		want []int
	}{
		{name: "empty mask", mask: 0, keep: Proc},
		{name: "only kept capabilities", mask: keepMask(Proc), keep: Proc},
		{name: "one extra below and one above", mask: keepMask(Proc) | 1<<0 | 1<<40, keep: Proc, want: []int{0, 40}},
		{name: "everything with nothing kept", mask: 0b1011, keep: nil, want: []int{0, 1, 3}},
		{name: "keep outside the mask is not reported", mask: 1 << SysAdmin, keep: []int{SysAdmin, SysTime}},
		{name: "keep mask ignores numbers out of range", mask: 1 << 63, keep: []int{63, 64, -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outside(tc.mask, tc.keep); !slices.Equal(got, tc.want) {
				t.Fatalf("outside(%#x, %v) = %v, want %v", tc.mask, tc.keep, got, tc.want)
			}
		})
	}
}

// TestForRuntime checks the measured keep lists. runc's holds everything
// proc's does and the four the user namespace costs the agent.
func TestForRuntime(t *testing.T) {
	cases := []struct {
		name     string
		runtime  string
		measured bool
		want     []int
	}{
		{name: "proc", runtime: "proc", measured: true, want: Proc},
		{name: "runc", runtime: "runc", measured: true, want: Runc},
		{name: "gvisor is not measured", runtime: "gvisor"},
		{name: "stub is not measured", runtime: "stub"},
		{name: "unknown", runtime: "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, measured := ForRuntime(tc.runtime)
			if measured != tc.measured || !slices.Equal(got, tc.want) {
				t.Fatalf("ForRuntime(%q) = %v, %v; want %v, %v", tc.runtime, got, measured, tc.want, tc.measured)
			}
		})
	}
}

// TestRuncSet checks what runc adds over proc, each named for Kubernetes, and
// what stays out. DAC_READ_SEARCH is covered by DAC_OVERRIDE and KILL by
// cgroup.kill, as the measurement showed.
func TestRuncSet(t *testing.T) {
	cases := []struct {
		name           string
		cap            int
		inRunc, inProc bool
	}{
		{name: "CHOWN", cap: Chown, inRunc: true},
		{name: "DAC_OVERRIDE", cap: DACOverride, inRunc: true},
		{name: "DAC_READ_SEARCH stays out", cap: DACReadSearch},
		{name: "KILL stays out", cap: Kill},
		{name: "SETGID", cap: SetGID, inRunc: true},
		{name: "SETUID", cap: SetUID, inRunc: true},
		{name: "SYS_ADMIN", cap: SysAdmin, inRunc: true, inProc: true},
		{name: "FOWNER stays out", cap: 3},
		{name: "MKNOD stays out", cap: 27},
		{name: "NET_RAW stays out", cap: 13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := slices.Contains(Runc, tc.cap); got != tc.inRunc {
				t.Fatalf("Runc has %d: %v, want %v", tc.cap, got, tc.inRunc)
			}
			if got := slices.Contains(Proc, tc.cap); got != tc.inProc {
				t.Fatalf("Proc has %d: %v, want %v", tc.cap, got, tc.inProc)
			}
			if tc.inRunc && Names[tc.cap] == "" {
				t.Fatalf("capability %d has no Kubernetes name", tc.cap)
			}
		})
	}
}
