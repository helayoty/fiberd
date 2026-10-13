package artifact_test

import (
	"runtime"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// TestComplete checks the seam every host-facts caller goes through. A
// platform that names all three facts is returned as is, and only the
// facts it leaves empty are detected. The libc is the fact that runs
// ldd, so a platform naming it is detected by the real code here, while
// the rows that leave it empty go through the stand-in.
func TestComplete(t *testing.T) {
	cases := []struct {
		name string
		real bool // the real detection, not the stand-in
		in   artifact.Platform
		want artifact.Platform
	}{
		{name: "all three named: nothing detected", in: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: "musl"},
			want: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: "musl"}},
		{name: "backend and templates ride along", in: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: "musl", Backend: "proc", Templates: "/t"},
			want: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: "musl", Backend: "proc", Templates: "/t"}},
		{name: "an empty libc is detected", in: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test"},
			want: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: fakePlatform.Libc}},
		{name: "an empty platform is the host", want: fakePlatform},
		{name: "arch and kernel come from the runtime and the kernel, no ldd", real: true, in: artifact.Platform{Libc: "none"},
			want: artifact.Platform{Arch: runtime.GOARCH, Libc: "none"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.real {
				fakeHost(t)
			}
			got := tc.in.Complete()
			if tc.real {
				if got.Kernel == "" {
					t.Fatal("no kernel detected")
				}
				tc.want.Kernel = got.Kernel
			}
			if got != tc.want {
				t.Fatalf("Complete(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}
