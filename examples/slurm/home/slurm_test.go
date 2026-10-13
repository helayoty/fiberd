package home_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"

	"github.com/helayoty/fiberd/examples/slurm/home"
)

func env(over map[string]string) func(string) string {
	base := map[string]string{
		"SLURM_JOB_ID": "4242", "SLURM_JOB_NAME": "fiberd-grant", "SLURM_JOB_USER": "heba", "SLURM_JOB_ACCOUNT": "ml",
		"SLURM_JOB_PARTITION": "gpu", "SLURMD_NODENAME": "localhost", "SLURM_JOB_NODELIST": "node[1-2]",
		"SLURM_CPUS_ON_NODE": "4", "SLURM_JOB_GRES": "gpu:2", "CUDA_VISIBLE_DEVICES": "0,1",
	}
	for k, v := range over {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

// fakeCgroup is a cgroup v2 mount with its controllers already delegated.
func fakeCgroup(t *testing.T) string {
	cg := filepath.Join(t.TempDir(), "cgroup")
	_ = os.MkdirAll(cg, 0o755)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0o644)
	return cg
}

// newHome builds a home on a fake cgroup mount. Each mod adjusts the
// config before New.
func newHome(t *testing.T, over map[string]string, probe []string, onEnd func(), mods ...func(*home.Config)) *home.Home {
	if onEnd == nil {
		onEnd = func() { t.Error("OnJobEnd called although the job never ended") }
	}
	cfg := home.Config{
		Env: env(over), GrantsDir: filepath.Join(t.TempDir(), "grants"), Poll: 20 * time.Millisecond, StaleTTL: 100 * time.Millisecond,
		CgroupMount: fakeCgroup(t), Family: endpoint.Inet4, Host: "10.9.8.7", ListenPort: "8484", Probe: probe, OnJobEnd: onEnd,
	}
	for _, m := range mods {
		m(&cfg)
	}
	h, err := home.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestHomeFromTheAllocation checks what the home reads from the job's
// environment and what it derives from that.
func TestHomeFromTheAllocation(t *testing.T) {
	h := newHome(t, nil, []string{}, nil)
	scope := func(name string) func() string {
		return func() string {
			for _, c := range h.Scope() {
				if c.Name == name {
					return c.Value
				}
			}
			return ""
		}
	}
	cases := []struct {
		name string
		got  func() string
		want string
	}{
		{"the home is named slurm", h.Name, "slurm"},
		{"the cgroup root is grants under the delegated root", func() string {
			r := h.CgroupRoot()
			return filepath.Join(filepath.Base(filepath.Dir(r)), filepath.Base(r))
		}, "cgroup/grants"},
		{"scope names the job id", scope("job_id"), "4242"},
		{"scope names the job name", scope("job_name"), "fiberd-grant"},
		{"scope names the user", scope("user"), "heba"},
		{"scope names the account", scope("account"), "ml"},
		{"scope names the partition", scope("partition"), "gpu"},
		{"scope names the node", scope("node"), "localhost"},
		{"scope names the nodelist", scope("nodelist"), "node[1-2]"},
		{"scope names the GRES", scope("gres"), "gpu:2"},
		{"scope names the CPUs", scope("cpus"), "4"},
		{"the endpoint host is the configured host", h.EndpointHost, "10.9.8.7"},
		{"the advertised endpoint is host:port", h.AdvertisedEndpoint, "10.9.8.7:8484"},
		{"Job is the allocation the environment names", func() string {
			j := h.Job()
			return fmt.Sprintf("%s %s %s %s %s %s %s %s %d", j.ID, j.Name, j.User, j.Account, j.Partition, j.Node, j.NodeList, j.GRES, j.CPUs)
		}, "4242 fiberd-grant heba ml gpu localhost node[1-2] gpu:2 4"},
		{"the default grants dir is the job's under /run/fiberd", func() string { return home.DefaultGrantsDir(h.Job().ID) }, "/run/fiberd/job-4242/grants"},
		{"publishing readiness is a no-op", func() string { return fmt.Sprint(h.PublishReady(context.Background(), "g", true)) }, "<nil>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.got(); got != tc.want {
				t.Fatalf("got %q, want %q (scope: %v)", got, tc.want, h.Scope())
			}
		})
	}
}

// TestDevices checks that the allocation's GRES is the device channel and its CPUs
// bound capacity.
func TestDevices(t *testing.T) {
	noCPUsNoGRES := map[string]string{"SLURM_CPUS_ON_NODE": "", "SLURM_JOB_GRES": "", "CUDA_VISIBLE_DEVICES": ""}
	cases := []struct {
		name    string
		env     map[string]string
		devs    []string // Config.Devices
		fibers  int
		kind    string
		detail  string
		devices string
		err     string
	}{
		{name: "the GRES and its GPUs, for fibers within the CPUs", fibers: 4,
			kind: "gres", detail: "gpu:2", devices: "/dev/nvidia0,/dev/nvidia1"},
		{name: "fibers.max above the allocation's CPUs is refused", fibers: 5, err: "4 CPUs"},
		{name: "unlimited fibers pass", fibers: 0,
			kind: "gres", detail: "gpu:2", devices: "/dev/nvidia0,/dev/nvidia1"},
		{name: "an allocation without a CPU count or GRES: no bound, no device channel", env: noCPUsNoGRES, fibers: 64},
		{name: "GPUs without a GRES string are a static device channel", env: map[string]string{"SLURM_JOB_GRES": ""}, fibers: 1,
			kind: "static", devices: "/dev/nvidia0,/dev/nvidia1"},
		{name: "SLURM_JOB_GPUS names the GPUs when CUDA_VISIBLE_DEVICES is unset",
			env: map[string]string{"SLURM_JOB_GRES": "", "CUDA_VISIBLE_DEVICES": "", "SLURM_JOB_GPUS": "2, 3"}, fibers: 1,
			kind: "static", devices: "/dev/nvidia2,/dev/nvidia3"},
		{name: "a GPU that is not an index is passed through as a path",
			env: map[string]string{"CUDA_VISIBLE_DEVICES": "/dev/dri/card0,,1"}, fibers: 1,
			kind: "gres", detail: "gpu:2", devices: "/dev/dri/card0,/dev/nvidia1"},
		{name: "configured devices replace the allocation's GPUs", devs: []string{"/dev/infiniband/uverbs0"}, fibers: 1,
			kind: "gres", detail: "gpu:2", devices: "/dev/infiniband/uverbs0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHome(t, tc.env, []string{}, nil, func(c *home.Config) { c.Devices = tc.devs })
			fc, release, err := h.Devices(context.Background(), core.Grant{UID: "g", FiberMax: tc.fibers})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("device channel for %d fibers = %v, want a refusal with %q", tc.fibers, err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			release()
			if fc.Kind != tc.kind || fc.Detail != tc.detail || strings.Join(fc.Devices, ",") != tc.devices {
				t.Fatalf("device channel = %+v, want %s %q devices %q", fc, tc.kind, tc.detail, tc.devices)
			}
		})
	}
}

func TestNewOutsideAValidAllocationIsAnError(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		cgroup bool // a fake cgroup mount, so only the cgroup can fail
		err    string
		is     error
	}{
		{name: "no SLURM_JOB_ID: not inside an allocation", env: map[string]string{"SLURM_JOB_ID": ""}, err: "SLURM_JOB_ID"},
		{name: "a CPU count that is not a number", env: map[string]string{"SLURM_CPUS_ON_NODE": "four"}, err: "SLURM_CPUS_ON_NODE"},
		{name: "a cgroup mount without the job step's cgroup files", err: "slurm: cgroup", is: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// An empty directory is a cgroup mount with nothing to delegate.
			cfg := home.Config{Env: env(tc.env), CgroupMount: t.TempDir()}
			_, err := home.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want one naming %s", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.is)
			}
		})
	}
}

// TestReadJob checks what the job's environment fills in and what falls
// back to the process.
func TestReadJob(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want home.Job
	}{
		{name: "every field from the job's environment", want: home.Job{ID: "4242", Name: "fiberd-grant", User: "heba", Account: "ml",
			Partition: "gpu", Node: "localhost", NodeList: "node[1-2]", GRES: "gpu:2", CPUs: 4}},
		{name: "USER stands in for SLURM_JOB_USER", env: map[string]string{"SLURM_JOB_USER": "", "USER": "fallback"},
			want: home.Job{ID: "4242", Name: "fiberd-grant", User: "fallback", Account: "ml",
				Partition: "gpu", Node: "localhost", NodeList: "node[1-2]", GRES: "gpu:2", CPUs: 4}},
		{name: "the host name stands in for SLURMD_NODENAME", env: map[string]string{"SLURMD_NODENAME": ""},
			want: home.Job{ID: "4242", Name: "fiberd-grant", User: "heba", Account: "ml",
				Partition: "gpu", Node: hostname, NodeList: "node[1-2]", GRES: "gpu:2", CPUs: 4}},
		{name: "no CPU count is zero, no bound", env: map[string]string{"SLURM_CPUS_ON_NODE": ""},
			want: home.Job{ID: "4242", Name: "fiberd-grant", User: "heba", Account: "ml",
				Partition: "gpu", Node: "localhost", NodeList: "node[1-2]", GRES: "gpu:2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := home.ReadJob(env(tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("job = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestNewReadsTheProcessEnvironment checks that a nil Env is the process's
// own environment, which is how fiberd-slurm runs inside a job.
func TestNewReadsTheProcessEnvironment(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		check func(h *home.Home) error
	}{
		{name: "the job comes from SLURM_* variables", env: map[string]string{"SLURM_JOB_ID": "77", "SLURM_JOB_USER": "ada"},
			check: func(h *home.Home) error {
				if j := h.Job(); j.ID != "77" || j.User != "ada" {
					return fmt.Errorf("job = %+v, want id 77 for ada", j)
				}
				return nil
			}},
		{name: "the GPUs come from CUDA_VISIBLE_DEVICES", env: map[string]string{"SLURM_JOB_ID": "77", "CUDA_VISIBLE_DEVICES": "3"},
			check: func(h *home.Home) error {
				fc, _, err := h.Devices(context.Background(), core.Grant{UID: "g"})
				if err != nil || strings.Join(fc.Devices, ",") != "/dev/nvidia3" {
					return fmt.Errorf("device channel = %+v, want /dev/nvidia3: %w", fc, err)
				}
				return nil
			}},
		{name: "the stale TTL defaults to 30s", env: map[string]string{"SLURM_JOB_ID": "77"},
			check: func(h *home.Home) error {
				now := time.Now()
				if !h.Health().Healthy(now.Add(29*time.Second)) || h.Health().Healthy(now.Add(31*time.Second)) {
					return errors.New("the issuer must become unreachable between 29s and 31s of silence")
				}
				return nil
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"SLURM_JOB_USER", "SLURM_CPUS_ON_NODE", "SLURM_JOB_GPUS", "CUDA_VISIBLE_DEVICES"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			h, err := home.New(home.Config{CgroupMount: fakeCgroup(t), Probe: []string{}, OnJobEnd: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.check(h); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestEndpointHost checks the address callers dial when no host is
// configured. It is the node name's address of the family, else one of
// this host's own addresses of the family.
func TestEndpointHost(t *testing.T) {
	// own checks that the address got is one of this host's non-loopback
	// addresses of the family, or "" when the host has none.
	own := func(v4 bool) func(string) error {
		return func(got string) error {
			addrs, err := net.InterfaceAddrs()
			if err != nil {
				return err
			}
			var cands []string
			for _, a := range addrs {
				n, ok := a.(*net.IPNet)
				if !ok || n.IP.IsLoopback() || (n.IP.To4() != nil) != v4 || (!v4 && !n.IP.IsGlobalUnicast()) {
					continue
				}
				cands = append(cands, n.IP.String())
			}
			if len(cands) == 0 {
				if got != "" {
					return fmt.Errorf("host = %q, want none: this host has no such address", got)
				}
				return nil
			}
			if got != cands[0] {
				return fmt.Errorf("host = %q, want the first of %v", got, cands)
			}
			return nil
		}
	}
	is := func(want string) func(string) error {
		return func(got string) error {
			if got != want {
				return fmt.Errorf("host = %q, want %q", got, want)
			}
			return nil
		}
	}
	cases := []struct {
		name   string
		node   string
		family endpoint.Family
		port   string
		check  func(string) error
		adv    string // the advertised endpoint, or "-" to skip the check
	}{
		{name: "an IPv4 node address for inet4", node: "10.1.2.3", family: endpoint.Inet4, port: "8484", check: is("10.1.2.3"), adv: "10.1.2.3:8484"},
		{name: "an IPv6 node address for inet6", node: "2001:db8::7", family: endpoint.Inet6, port: "8484", check: is("2001:db8::7"), adv: "[2001:db8::7]:8484"},
		{name: "unix serves callers over inet4", node: "10.1.2.3", family: endpoint.Unix, port: "8484", check: is("10.1.2.3"), adv: "10.1.2.3:8484"},
		{name: "no family is inet4", node: "10.1.2.3", port: "8484", check: is("10.1.2.3"), adv: "10.1.2.3:8484"},
		{name: "no listen port: nothing to advertise", node: "10.1.2.3", family: endpoint.Inet4, check: is("10.1.2.3"), adv: ""},
		{name: "a loopback node falls back to this host's IPv4 address", node: "127.0.0.1", family: endpoint.Inet4, check: own(true), adv: "-"},
		{name: "an IPv4 node for inet6 falls back to this host's IPv6 address", node: "10.1.2.3", family: endpoint.Inet6, check: own(false), adv: "-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHome(t, map[string]string{"SLURMD_NODENAME": tc.node}, []string{}, nil, func(c *home.Config) {
				c.Host, c.Family, c.ListenPort = "", tc.family, tc.port
			})
			if err := tc.check(h.EndpointHost()); err != nil {
				t.Fatal(err)
			}
			if tc.adv != "-" {
				if got := h.AdvertisedEndpoint(); got != tc.adv {
					t.Fatalf("advertised = %q, want %q", got, tc.adv)
				}
			}
		})
	}
}

// TestGrants checks that a *.jwt file in the grants directory is a grant
// added, and that a directory that cannot exist is an error.
func TestGrants(t *testing.T) {
	cases := []struct {
		name  string
		dir   func(t *testing.T) string
		token string
		err   bool
	}{
		{name: "a grant file is delivered with its token", dir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "grants") }, token: "tok-1"},
		{name: "a grants dir under a regular file is an error", dir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "grants")
		}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.dir(t)
			h := newHome(t, nil, []string{}, nil, func(c *home.Config) { c.GrantsDir = dir })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch, err := h.Grants(ctx)
			if tc.err {
				if err == nil {
					t.Fatal("Grants succeeded on a directory that cannot be made")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "g.jwt"), []byte(tc.token), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case ev := <-ch:
				if string(ev.Token) != tc.token {
					t.Fatalf("event = %+v, want token %q", ev, tc.token)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no grant event for the new file")
			}
			// Delivery closes once the context ends.
			cancel()
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
				case <-time.After(5 * time.Second):
					t.Fatal("delivery stayed open after its context ended")
				}
			}
		})
	}
}

// TestIssuerReachability checks that reachability follows the probe and
// that SetIssuerReachable overrides it. The probe fails and ends Run's
// context on its first call, so the steps start from one failed probe
// and share that home, in order.
func TestIssuerReachability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	down := func(context.Context, []string) ([]byte, error) {
		cancel()
		return []byte("slurmctld down"), errors.New("exit status 1")
	}
	h := newHome(t, nil, []string{"scontrol"}, nil, func(c *home.Config) { c.RunProbe = down })
	h.Run(ctx)
	steps := []struct {
		name    string
		act     func()
		at      time.Duration // how far past now reachability is judged
		healthy bool
	}{
		{"a failed probe leaves the boot sync, so the issuer is reachable within the stale TTL", func() {}, 0, true},
		{"the probe failing past the stale TTL marks the issuer unreachable", func() {}, 100 * time.Millisecond, false},
		{"SetIssuerReachable(true) marks the issuer reachable again", func() { h.SetIssuerReachable(true) }, 0, true},
		{"SetIssuerReachable(false) marks the issuer unreachable", func() { h.SetIssuerReachable(false) }, 0, false},
	}
	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			step.act()
			if got := h.Health().Healthy(time.Now().Add(step.at)); got != step.healthy {
				t.Fatalf("healthy = %v, want %v", got, step.healthy)
			}
		})
		if !ok {
			return // later steps build on this one
		}
	}
}
