package artifact_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

func TestParityCheck(t *testing.T) {
	host := artifact.Platform{Arch: "arm64", Kernel: "6.10.14-linuxkit", Libc: "(gnu libc) 2.36"}
	proc := host
	proc.Backend = "proc"
	off := artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}
	cases := []struct {
		name   string
		parity artifact.Parity
		local  artifact.Platform // the restoring side; zero = host
		want   artifact.Platform // what the artifact was built on
		ok     bool
	}{
		{name: "identical strict", parity: artifact.Strict, want: host, ok: true},
		{name: "zero value is strict", parity: artifact.Parity{}, want: host, ok: true},
		{name: "unknown facts pass (old publisher)", parity: artifact.Strict, want: artifact.Platform{}, ok: true},
		{name: "arch never relaxes", parity: off,
			want: artifact.Platform{Arch: "amd64", Kernel: host.Kernel, Libc: host.Libc}},
		{name: "patch release differs, exact", parity: artifact.Strict,
			want: artifact.Platform{Arch: "arm64", Kernel: "6.10.2-linuxkit", Libc: host.Libc}},
		{name: "patch release differs, series", parity: artifact.Parity{Kernel: artifact.ParitySeries},
			want: artifact.Platform{Arch: "arm64", Kernel: "6.10.2-linuxkit", Libc: host.Libc}, ok: true},
		{name: "minor differs, series", parity: artifact.Parity{Kernel: artifact.ParitySeries},
			want: artifact.Platform{Arch: "arm64", Kernel: "6.11.0", Libc: host.Libc}},
		{name: "kernel off", parity: artifact.Parity{Kernel: artifact.ParityOff},
			want: artifact.Platform{Arch: "arm64", Kernel: "5.4.0", Libc: host.Libc}, ok: true},
		{name: "libc differs", parity: artifact.Strict,
			want: artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: "(gnu libc) 2.31"}},
		{name: "libc off", parity: artifact.Parity{Libc: artifact.ParityOff},
			want: artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: "(gnu libc) 2.31"}, ok: true},
		{name: "backend unknown on either side passes", parity: artifact.Strict,
			want: artifact.Platform{Arch: "arm64", Kernel: host.Kernel, Libc: host.Libc, Backend: "proc"}, ok: true},
		{name: "same backend on both sides passes", parity: artifact.Strict, local: proc,
			want: artifact.Platform{Arch: "arm64", Backend: "proc"}, ok: true},
		{name: "backend never relaxes", parity: off, local: proc,
			want: artifact.Platform{Arch: "arm64", Backend: "gvisor"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local := c.local
			if local == (artifact.Platform{}) {
				local = host
			}
			err := c.parity.Check(local, c.want)
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
		name string
		in   string
		want artifact.Parity
		ok   bool
	}{
		{name: "empty is strict", in: "", want: artifact.Strict, ok: true},
		{name: "strict", in: "strict", want: artifact.Strict, ok: true},
		{name: "off relaxes kernel and libc", in: "off", want: artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, ok: true},
		{name: "kernel series keeps libc exact", in: "kernel=series", want: artifact.Parity{Kernel: artifact.ParitySeries, Libc: artifact.ParityExact}, ok: true},
		{name: "comma-separated with spaces", in: "kernel=off, libc=off", want: artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, ok: true},
		{name: "libc has no series", in: "libc=series"},
		{name: "an unknown kernel level", in: "kernel=minor"},
		{name: "arch cannot be relaxed", in: "arch=off"},
		{name: "a fact without a level", in: "kernel"},
		{name: "an unknown fact", in: "cpu=off"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := artifact.ParseParity(c.in)
			if c.ok != (err == nil) {
				t.Fatalf("%q: err = %v, ok = %v", c.in, err, c.ok)
			}
			if c.ok && got != c.want {
				t.Fatalf("%q = %+v, want %+v", c.in, got, c.want)
			}
			// What String prints parses back to the same levels.
			if again, err := artifact.ParseParity(got.String()); c.ok && (err != nil || again != got) {
				t.Fatalf("ParseParity(%q) = %+v, %v; want %+v", got.String(), again, err, got)
			}
		})
	}
}

func TestKernelSeries(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{name: "patch and local version dropped", in: "6.10.14-linuxkit", want: "6.10"},
		{name: "distro suffix dropped", in: "5.15.0-1055-azure", want: "5.15"},
		{name: "already a series", in: "6.1", want: "6.1"},
		{name: "major alone stays", in: "6", want: "6"},
		{name: "suffix on the minor dropped", in: "6.8-rc3", want: "6.8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := artifact.KernelSeries(c.in); got != c.want {
				t.Fatalf("KernelSeries(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestPlatformAnnotationsRoundTrip(t *testing.T) {
	annotated := func(p artifact.Platform) map[string]string {
		m := map[string]string{}
		p.Annotate(m)
		return m
	}
	explicit := artifact.Platform{Arch: "amd64", Kernel: "6.8.0", Libc: "(gnu libc) 2.39"}
	gvisor := artifact.Platform{Arch: "amd64", Backend: "gvisor"}
	cases := []struct {
		name string
		m    map[string]string
		want artifact.Platform
		ok   bool
	}{
		{name: "an annotated platform reads back", m: annotated(explicit), want: explicit, ok: true},
		{name: "the detected host platform reads back", m: annotated(artifact.Host()), want: artifact.Host(), ok: true},
		{name: "a backend reads back", m: annotated(gvisor), want: gvisor, ok: true},
		{name: "a backend alone is a platform", m: map[string]string{artifact.AnnotationBackend: "proc"},
			want: artifact.Platform{Backend: "proc"}, ok: true},
		{name: "empty annotations report no platform", m: map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := artifact.PlatformFromAnnotations(c.m)
			if ok != c.ok || (c.ok && got != c.want) {
				t.Fatalf("PlatformFromAnnotations = %+v %v, want %+v %v", got, ok, c.want, c.ok)
			}
			if _, has := c.m[artifact.AnnotationBackend]; has != (c.want.Backend != "") {
				t.Fatalf("backend annotation present = %v for %+v", has, c.want)
			}
		})
	}
}

func TestStrings(t *testing.T) {
	cases := []struct {
		name string
		got  fmt.Stringer
		want string
	}{
		{name: "a platform", got: artifact.Platform{Arch: "arm64", Kernel: "6.10.14", Libc: "(gnu libc) 2.36"},
			want: "arm64/6.10.14/(gnu libc) 2.36"},
		{name: "a platform with its backend", got: artifact.Platform{Arch: "arm64", Kernel: "6.10.14", Libc: "musl", Backend: "gvisor"},
			want: "arm64/6.10.14/musl/gvisor"},
		{name: "a config's build host, without a backend", got: artifact.Config{Arch: "amd64", Kernel: "6.8.0", Libc: "glibc"}.Platform(),
			want: "amd64/6.8.0/glibc"},
		{name: "the zero parity is strict", got: artifact.Parity{}, want: "kernel=exact,libc=exact"},
		{name: "a relaxed parity", got: artifact.Parity{Kernel: artifact.ParitySeries, Libc: artifact.ParityOff}, want: "kernel=series,libc=off"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if s := c.got.String(); s != c.want {
				t.Fatalf("String() = %q, want %q", s, c.want)
			}
		})
	}
}
