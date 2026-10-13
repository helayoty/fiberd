//go:build linux && integration

package katatest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"

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
	OwnGroup   bool     `json:"own_group"` // the daemon leads its own process group
	Socket     string   `json:"socket"`    // the listener handed over as fd 3
	Err        string   `json:"err"`
}

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		os.Exit(fakeShimDaemon())
	}
	dir := filepath.Join(defaults.DefaultStateDir, "s")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "skipping kata tests: shim sockets live under %s: %v (run under hack/dev/run.sh)\n", dir, err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeShimDaemon() int {
	rep := childReport{Args: os.Args[1:], GOMAXPROCS: os.Getenv("GOMAXPROCS"), OwnGroup: syscall.Getpgrp() == os.Getpid()}
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

// bundle writes a container bundle whose config.json carries annotations.
func bundle(t *testing.T, annotations map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(map[string]any{"ociVersion": "1.1.0", "annotations": annotations})
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestManagerStartExecsThisBinary checks the real spawn of the shim
// daemon, which the unit tests of examples/kata/shim run in process. The
// daemon is this binary, run in the bundle with containerd's flags,
// GOMAXPROCS=2, its own process group and the shim socket as fd 3.
func TestManagerStartExecsThisBinary(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		debug       bool
		group       string // the id the socket address derives from
	}{
		{name: "a container outside a Pod, grouped by its id", annotations: map[string]string{"io.kubernetes.cri.container-type": "container"}, group: "c1"},
		{name: "debug is passed on", annotations: map[string]string{"io.kubernetes.cri.container-type": "container"}, debug: true, group: "c1"},
		{name: "a Pod's container, grouped by the sandbox id", annotations: map[string]string{"io.kubernetes.cri.sandbox-id": "sb-1"}, group: "sb-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
			opts := shim.StartOpts{Address: filepath.Join(t.TempDir(), "containerd.sock"), Debug: tc.debug}
			dir := bundle(t, tc.annotations)
			t.Chdir(dir)
			t.Setenv(childEnv, "1")
			address, err := shim.SocketAddress(ctx, opts.Address, tc.group, false)
			if err != nil {
				t.Fatal(err)
			}
			path := strings.TrimPrefix(address, "unix://")
			t.Cleanup(func() { _ = os.RemoveAll(path) })

			params, err := fshim.NewManager().Start(ctx, "c1", opts)
			want := shim.BootstrapParams{Version: 3, Address: address, Protocol: "ttrpc"}
			if err != nil || params != want {
				t.Fatalf("start = %+v (%v), want %+v", params, err, want)
			}
			rep := waitChild(t, dir)
			wantArgs := []string{"-namespace", "k8s.io", "-id", "c1", "-address", opts.Address}
			if tc.debug {
				wantArgs = append(wantArgs, "-debug")
			}
			realDir, _ := filepath.EvalSymlinks(dir)
			gotDir, _ := filepath.EvalSymlinks(rep.Dir)
			if !slices.Equal(rep.Args, wantArgs) || gotDir != realDir || rep.GOMAXPROCS != "2" || !rep.OwnGroup || rep.Socket != path || rep.Err != "" {
				t.Fatalf("the shim daemon saw %+v, want args %v in %s with GOMAXPROCS=2, its own process group and the socket %s",
					rep, wantArgs, realDir, path)
			}
		})
	}
}
