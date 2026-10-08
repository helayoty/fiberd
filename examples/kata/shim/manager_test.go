package shim_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"

	fshim "github.com/helayoty/fiberd/examples/kata/shim"
)

// childEnv makes this test binary act as the shim daemon Manager.Start
// spawns. Start passes its environment on, so a test sets it with
// t.Setenv.
const childEnv = "FIBERD_KATA_TEST_SHIM_CHILD"

// childReport is what the spawned shim saw. It writes it to child.json in
// its working directory.
type childReport struct {
	Args       []string `json:"args"`
	Dir        string   `json:"dir"`
	GOMAXPROCS string   `json:"gomaxprocs"`
	Socket     string   `json:"socket"` // the listener handed over as fd 3
	Err        string   `json:"err"`
}

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		os.Exit(fakeShimDaemon())
	}
	os.Exit(m.Run())
}

func fakeShimDaemon() int {
	rep := childReport{Args: os.Args[1:], GOMAXPROCS: os.Getenv("GOMAXPROCS")}
	rep.Dir, _ = os.Getwd()
	if l, err := net.FileListener(os.NewFile(3, "socket")); err == nil {
		rep.Socket = l.Addr().String()
	} else {
		rep.Err = err.Error()
	}
	b, _ := json.Marshal(rep)
	// Write then rename, so the test never reads half a report.
	if os.WriteFile("child.json.tmp", b, 0o600) != nil || os.Rename("child.json.tmp", "child.json") != nil {
		return 1
	}
	return 0
}

// waitChild polls for the spawned shim's report.
func waitChild(t *testing.T, dir string) childReport {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "child.json"))
		if err == nil {
			var rep childReport
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			return rep
		}
		if time.Now().After(deadline) {
			t.Fatal("the shim daemon was not spawned")
		}
		time.Sleep(10 * time.Millisecond) // polling a file the child writes, not synchronising
	}
}

// needSocketRoot skips unless this process may make shim sockets where
// containerd keeps them (root, as in the dev container).
func needSocketRoot(t *testing.T) {
	t.Helper()
	dir := filepath.Join(defaults.DefaultStateDir, "s")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("shim sockets live under %s: %v", dir, err)
	}
	f, err := os.CreateTemp(dir, "probe")
	if err != nil {
		t.Skipf("shim sockets live under %s: %v", dir, err)
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
}

// chdirGone makes the working directory one that no longer exists, or
// skips where the OS still reports the removed directory's path.
func chdirGone(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this OS still reports a removed working directory")
	}
}

func TestManagerIdentity(t *testing.T) {
	m := fshim.NewManager()
	info, err := m.Info(context.Background(), strings.NewReader(""))
	cases := []struct {
		name      string
		got, want string
	}{
		{"Name is the runtime_type containerd's config names", m.Name(), "io.containerd.fiberd.v1"},
		{"Info names the runtime", info.GetName(), fshim.RuntimeName},
		{"Info carries the version", info.GetVersion().GetVersion(), "0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err != nil || tc.got != tc.want {
				t.Fatalf("got %q (%v), want %q", tc.got, err, tc.want)
			}
		})
	}
}

// TestManagerStart checks how containerd gets a shim for a container. It
// reuses the Pod's running shim when there is one, and spawns a fresh one
// otherwise. Cases that make sockets under containerd's state dir need root.
func TestManagerStart(t *testing.T) {
	cases := []struct {
		name        string
		noNS        bool
		goneCwd     bool
		annotations map[string]string // the bundle's config.json, or nil for none
		debug       bool
		existing    string // what is at the socket path first, "live", "stale" or "dir"
		group       string // the id the address derives from, or empty for the container's
		spawn       bool
		errIs       func(error) bool
		errHas      string
	}{
		{name: "a context without a namespace is refused", noNS: true, errIs: errdefs.IsFailedPrecondition},
		{name: "a working directory that is gone is an error", goneCwd: true,
			errIs: func(err error) bool { return errors.Is(err, fs.ErrNotExist) }},
		{name: "a container outside a Pod gets its own shim: this binary, spawned",
			annotations: map[string]string{criType: "container"}, spawn: true},
		{name: "debug is passed on, and a bundle without a spec is grouped by the container's id",
			debug: true, spawn: true},
		{name: "a Pod's containers are grouped by the sandbox id",
			annotations: map[string]string{criSandboxID: "sb-1"}, group: "sb-1", spawn: true},
		{name: "the Pod's shim is up: its address, after probing it, and nothing spawned",
			annotations: map[string]string{criSandboxID: "sb-2"}, group: "sb-2", existing: "live"},
		{name: "a dead shim's socket is replaced and a shim spawned",
			annotations: map[string]string{criSandboxID: "sb-3"}, group: "sb-3", existing: "stale", spawn: true},
		{name: "a socket path that cannot be cleared is an error",
			annotations: map[string]string{criSandboxID: "sb-4"}, group: "sb-4", existing: "dir",
			errIs: func(err error) bool { return errors.Is(err, syscall.ENOTEMPTY) }, errHas: "remove stale shim socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
			if tc.noNS {
				ctx = context.Background()
			}
			id := "c1"
			opts := shim.StartOpts{Address: filepath.Join(t.TempDir(), "containerd.sock"), Debug: tc.debug}
			if tc.noNS || tc.goneCwd {
				if tc.goneCwd {
					chdirGone(t)
				}
				_, err := fshim.NewManager().Start(ctx, id, opts)
				if !tc.errIs(err) {
					t.Fatalf("start = %v, want the expected error", err)
				}
				return
			}
			needSocketRoot(t)
			dir := t.TempDir()
			if tc.annotations != nil {
				dir = bundle(t, tc.annotations)
			}
			t.Chdir(dir)
			t.Setenv(childEnv, "1")
			group := tc.group
			if group == "" {
				group = id
			}
			address, err := shim.SocketAddress(ctx, opts.Address, group, false)
			if err != nil {
				t.Fatal(err)
			}
			path := strings.TrimPrefix(address, "unix://")
			t.Cleanup(func() { _ = os.RemoveAll(path) })
			var live *net.UnixListener
			switch tc.existing {
			case "live":
				if live, err = shim.NewSocket(address); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = live.Close() })
			case "stale":
				l, err := shim.NewSocket(address)
				if err != nil {
					t.Fatal(err)
				}
				l.SetUnlinkOnClose(false)
				_ = l.Close()
			case "dir":
				if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			params, err := fshim.NewManager().Start(ctx, id, opts)
			if tc.errIs != nil {
				if !tc.errIs(err) || !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("start = %v, want an error naming %q", err, tc.errHas)
				}
				return
			}
			want := shim.BootstrapParams{Version: 3, Address: address, Protocol: "ttrpc"}
			if err != nil || params != want {
				t.Fatalf("start = %+v (%v), want %+v", params, err, want)
			}
			if live != nil {
				// Start dialled the running shim to see it is up.
				_ = live.SetDeadline(time.Now().Add(5 * time.Second))
				conn, err := live.Accept()
				if err != nil {
					t.Fatalf("the running shim was not probed: %v", err)
				}
				_ = conn.Close()
			}
			if !tc.spawn {
				return
			}
			rep := waitChild(t, dir)
			wantArgs := []string{"-namespace", "k8s.io", "-id", id, "-address", opts.Address}
			if tc.debug {
				wantArgs = append(wantArgs, "-debug")
			}
			realDir, _ := filepath.EvalSymlinks(dir)
			gotDir, _ := filepath.EvalSymlinks(rep.Dir)
			if !slices.Equal(rep.Args, wantArgs) || gotDir != realDir || rep.GOMAXPROCS != "2" || rep.Socket != path {
				t.Fatalf("the shim daemon saw %+v, want args %v in %s with GOMAXPROCS=2 and the socket %s",
					rep, wantArgs, realDir, path)
			}
		})
	}
}

// TestManagerStop checks the cleanup containerd runs for a container whose
// shim is gone. The fiber the bundle records is stopped as the Pod asked,
// and the record is removed.
func TestManagerStop(t *testing.T) {
	fake := newFakeHome(t)
	cases := []struct {
		name         string
		record       string // fiberd.json, or empty for none
		goneCwd      bool
		wantParks    []string
		wantReleases []string
	}{
		{name: "no record: nothing to stop"},
		{name: "a fiber the Pod parks on stop is parked",
			record: `{"home":"` + fake.addr + `","fiber_id":"f-park","session":"s","on_stop":"park"}`, wantParks: []string{"f-park"}},
		{name: "a fiber is released by default",
			record: `{"home":"` + fake.addr + `","fiber_id":"f-rel","session":"s"}`, wantReleases: []string{"f-rel"}},
		{name: "a record without a fiber is removed, nothing stopped",
			record: `{"home":"` + fake.addr + `"}`},
		{name: "a record that is not JSON is removed, nothing stopped", record: `{"home":`},
		{name: "a home that is down does not keep the record",
			record: `{"home":"127.0.0.1:1","fiber_id":"f-down"}`},
		{name: "a home address the shim cannot dial does not keep the record",
			record: `{"home":"%zz","fiber_id":"f-bad"}`},
		{name: "a working directory that is gone is an error", goneCwd: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake.reset()
			if tc.goneCwd {
				chdirGone(t)
				if _, err := fshim.NewManager().Stop(context.Background(), "c1"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("stop = %v, want the working directory's error", err)
				}
				return
			}
			// containerd runs the cleanup in the container's bundle,
			// <state>/<namespace>/<id>.
			dir := filepath.Join(t.TempDir(), "k8s.io", "c1")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.record != "" {
				if err := os.WriteFile(filepath.Join(dir, fshim.StateFile), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			before := time.Now()
			st, err := fshim.NewManager().Stop(context.Background(), "c1")
			if err != nil || st.ExitStatus != 137 || st.ExitedAt.Before(before) || st.ExitedAt.After(time.Now()) {
				t.Fatalf("stop = %+v (%v), want exit 137 now", st, err)
			}
			if _, ok := readState(t, dir); ok && tc.record != "" {
				t.Fatal("the fiber record survived the cleanup")
			}
			_, parks, releases := fake.seen()
			if !slices.Equal(parks, tc.wantParks) || !slices.Equal(releases, tc.wantReleases) {
				t.Fatalf("home saw parks %v releases %v, want %v %v", parks, releases, tc.wantParks, tc.wantReleases)
			}
		})
	}
}

// pluginOf registers an instance as containerd's shim would.
func pluginOf(t *testing.T, set *plugin.Set, typ plugin.Type, id string, inst any) {
	t.Helper()
	reg := plugin.Registration{Type: typ, ID: id, InitFn: func(*plugin.InitContext) (any, error) { return inst, nil }}
	if err := set.Add(reg.Init(plugin.NewContext(context.Background(), set, nil))); err != nil {
		t.Fatal(err)
	}
}

// TestRegisterPlugin checks the task service's registration with
// containerd's shim plugin registry, and what it needs to start.
func TestRegisterPlugin(t *testing.T) {
	cases := []struct {
		name      string
		publisher any // the event plugin's instance, or nil for none
		shutdown  any // the internal shutdown plugin's instance, or nil for none
		errIs     func(error) bool
	}{
		{name: "with containerd's publisher and shutdown service it serves tasks",
			publisher: &publisher{}, shutdown: newShutdownStub()},
		{name: "without a publisher it fails", shutdown: newShutdownStub(),
			errIs: func(err error) bool { return errors.Is(err, plugin.ErrPluginNotFound) }},
		{name: "without a shutdown service it fails", publisher: &publisher{},
			errIs: func(err error) bool { return errors.Is(err, plugin.ErrPluginNotFound) }},
		{name: "an event plugin that is not a publisher is an invalid argument",
			publisher: "not a publisher", shutdown: newShutdownStub(), errIs: errdefs.IsInvalidArgument},
		{name: "a shutdown plugin that is not a shutdown service is an invalid argument",
			publisher: &publisher{}, shutdown: "not a shutdown service", errIs: errdefs.IsInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry.Reset()
			t.Cleanup(registry.Reset)
			fshim.RegisterPlugin()
			var task *plugin.Registration
			for _, r := range registry.Graph(func(*plugin.Registration) bool { return false }) {
				if r.Type == plugins.TTRPCPlugin && r.ID == "task" {
					task = &r
				}
			}
			if task == nil {
				t.Fatal("no task service registered")
			}
			if want := []plugin.Type{plugins.EventPlugin, plugins.InternalPlugin}; !slices.Equal(task.Requires, want) {
				t.Fatalf("requires %v, want %v", task.Requires, want)
			}
			set := plugin.NewPluginSet()
			if tc.publisher != nil {
				pluginOf(t, set, plugins.EventPlugin, "publisher", tc.publisher)
			}
			if tc.shutdown != nil {
				pluginOf(t, set, plugins.InternalPlugin, "shutdown", tc.shutdown)
			}
			ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
			inst, err := task.Init(plugin.NewContext(ctx, set, nil)).Instance()
			if tc.errIs != nil {
				if !tc.errIs(err) {
					t.Fatalf("init = %v, want the expected error", err)
				}
				return
			}
			s, ok := inst.(*fshim.Service)
			if err != nil || !ok {
				t.Fatalf("init = %T (%v), want the task service", inst, err)
			}
			if _, err := s.Create(context.Background(), &taskAPI.CreateTaskRequest{ID: "sb",
				Bundle: bundle(t, map[string]string{criType: "sandbox"})}); err != nil {
				t.Fatal(err)
			}
			pub, sd := tc.publisher.(*publisher), tc.shutdown.(*shutdownStub)
			pub.mu.Lock()
			defer pub.mu.Unlock()
			if len(pub.events) != 1 || pub.events[0].ns != "k8s.io" {
				t.Fatalf("events %+v, want one create in k8s.io on containerd's publisher", pub.events)
			}
			sd.mu.Lock()
			defer sd.mu.Unlock()
			if len(sd.callbacks) != 1 {
				t.Fatalf("%d shutdown callbacks, want the service's one", len(sd.callbacks))
			}
		})
	}
}
