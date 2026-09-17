package artifact_test

import (
	"errors"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

func TestParityCheck(t *testing.T) {
	host := artifact.Platform{Arch: "arm64", Kernel: "6.10.14-linuxkit", Libc: "(gnu libc) 2.36"}
	cases := []struct {
		name   string
		parity artifact.Parity
		want   artifact.Platform
		ok     bool
	}{
		{"identical strict", artifact.Strict, host, true},
		{"zero value is strict", artifact.Parity{}, host, true},
		{"unknown facts pass (old publisher)", artifact.Strict, artifact.Platform{}, true},
		{"arch never relaxes", artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff},
			artifact.Platform{Arch: "amd64", Kernel: host.Kernel, Libc: host.Libc}, false},
		{"patch release differs, exact", artifact.Strict,
			artifact.Platform{Arch: "arm64", Kernel: "6.10.2-linuxkit", Libc: host.Libc}, false},
		{"patch release differs, series", artifact.Parity{Kernel: artifact.ParitySeries},
			artifact.Platform{Arch: "arm64", Kernel: "6.10.2-linuxkit", Libc: host.Libc}, true},
		{"minor differs, series", artifact.Parity{Kernel: artifact.ParitySeries},
			artifact.Platform{Arch: "arm64", Kernel: "6.11.0", Libc: host.Libc}, false},
		{"kernel off", artifact.Parity{Kernel: artifact.ParityOff},
			artifact.Platform{Arch: "arm64", Kernel: "5.4.0", Libc: host.Libc}, true},
		{"libc differs", artifact.Strict,
			artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: "(gnu libc) 2.31"}, false},
		{"libc off", artifact.Parity{Libc: artifact.ParityOff},
			artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: "(gnu libc) 2.31"}, true},
		{"backend unknown on either side passes", artifact.Strict,
			artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: host.Libc, Backend: "proc"}, true},
	}
	proc := host
	proc.Backend = "proc"
	if err := artifact.Strict.Check(proc, artifact.Platform{Arch: "arm64", Backend: "proc"}); err != nil {
		t.Fatalf("same backend: %v", err)
	}
	relaxed := artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}
	if err := relaxed.Check(proc, artifact.Platform{Arch: "arm64", Backend: "gvisor"}); !errors.Is(err, artifact.ErrParity) {
		t.Fatalf("backend never relaxes: %v", err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.parity.Check(host, c.want)
			if c.ok && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if !c.ok && !errors.Is(err, artifact.ErrParity) {
				t.Fatalf("err = %v, want ErrParity", err)
			}
		})
	}
}

func TestParseParity(t *testing.T) {
	cases := []struct {
		in   string
		want artifact.Parity
		ok   bool
	}{
		{"", artifact.Strict, true},
		{"strict", artifact.Strict, true},
		{"off", artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, true},
		{"kernel=series", artifact.Parity{Kernel: artifact.ParitySeries, Libc: artifact.ParityExact}, true},
		{"kernel=off, libc=off", artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, true},
		{"libc=series", artifact.Parity{}, false},
		{"arch=off", artifact.Parity{}, false},
		{"kernel", artifact.Parity{}, false},
		{"cpu=off", artifact.Parity{}, false},
	}
	for _, c := range cases {
		got, err := artifact.ParseParity(c.in)
		if c.ok != (err == nil) {
			t.Errorf("%q: err = %v, ok = %v", c.in, err, c.ok)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("%q = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestKernelSeries(t *testing.T) {
	for in, want := range map[string]string{
		"6.10.14-linuxkit": "6.10", "5.15.0-1055-azure": "5.15", "6.1": "6.1", "6": "6", "6.8-rc3": "6.8",
	} {
		if got := artifact.KernelSeries(in); got != want {
			t.Errorf("KernelSeries(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlatformAnnotationsRoundTrip(t *testing.T) {
	p := artifact.Platform{Arch: "amd64", Kernel: "6.8.0", Libc: "(gnu libc) 2.39"}
	m := map[string]string{}
	p.Annotate(m)
	got, ok := artifact.PlatformFromAnnotations(m)
	if !ok || got != p {
		t.Fatalf("round trip = %+v %v", got, ok)
	}
	if _, ok := artifact.PlatformFromAnnotations(map[string]string{}); ok {
		t.Fatal("empty annotations reported a platform")
	}
	if artifact.Host().Arch == "" {
		t.Fatal("host arch empty")
	}
}
