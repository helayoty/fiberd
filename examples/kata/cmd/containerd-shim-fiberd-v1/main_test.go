package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"google.golang.org/protobuf/proto"

	fshim "github.com/helayoty/fiberd/examples/kata/shim"
)

// runMain runs main as containerd runs the binary, with args, and returns
// what it printed. main parses the process's flags and registers the task
// plugin, so both are reset around it.
func runMain(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
	t.Cleanup(func() {
		os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout
		registry.Reset()
	})
	os.Args = append([]string{"containerd-shim-fiberd-v1"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Stdout = out
	registry.Reset()

	main()

	os.Stdout = oldStdout
	_ = out.Close()
	b, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMainProbes checks the binary's answers to containerd's probes,
// which need no running containerd: -info for the runtime's identity and
// -v for its version.
func TestMainProbes(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		check func(t *testing.T, out []byte)
	}{
		{"-info answers with the fiberd runtime", []string{"-info"}, func(t *testing.T, out []byte) {
			var info types.RuntimeInfo
			if err := proto.Unmarshal(out, &info); err != nil {
				t.Fatalf("-info printed %q: %v", out, err)
			}
			if info.GetName() != fshim.RuntimeName || info.GetVersion().GetVersion() != "0.1" {
				t.Fatalf("-info = %v, want %s 0.1", &info, fshim.RuntimeName)
			}
		}},
		{"-v names the binary", []string{"-v"}, func(t *testing.T, out []byte) {
			if !strings.HasPrefix(string(out), "containerd-shim-fiberd-v1:\n") || !strings.Contains(string(out), "Version:") {
				t.Fatalf("-v printed %q", out)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runMain(t, tc.args...)
			tc.check(t, out)
			registered := false
			for _, r := range registry.Graph(func(*plugin.Registration) bool { return false }) {
				registered = registered || (r.Type == plugins.TTRPCPlugin && r.ID == "task")
			}
			if !registered {
				t.Fatal("main did not register the task service")
			}
		})
	}
}
