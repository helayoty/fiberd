//go:build linux && integration

package pythontest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRulesRefuseAtServe pins that a template which breaks a rule of the
// SDK never warms. serve() refuses before the first fork with a message
// that names the rule and the fix, which lands in the zygote's log, and
// the warm fails. The escape hatch, threads="warn", warms and clones
// with the thread alive in the zygote and absent from the fiber.
func TestRulesRefuseAtServe(t *testing.T) {
	cases := []struct {
		name     string
		template string
		// want is what the zygote's log must say when the warm fails.
		// Empty means the template warms and a clone answers ping.
		want []string
	}{
		{name: "a thread at serve is refused by name", template: "threaded.py",
			want: []string{"TemplateError", "serve() needs one thread, and this process has 1 more:", "(tid "}},
		{name: "an open socket at serve is refused by descriptor", template: "opensocket.py",
			want: []string{"TemplateError", "serve() needs no open socket", "is a socket (socket:["}},
		{name: "serve without init is refused", template: "noinit.py",
			want: []string{"TemplateError", "init() did not run in this process"}},
		{name: "threads=warn warms and clones", template: "warnthreads.py"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := newRuntime(t, python+" "+filepath.Join(testdata, tc.template))
			g := core.Grant{UID: "grule", TemplateDigest: "sha256:py", WBudgetBytes: 64 << 20}
			err := rt.PrepareTemplate(ctx, g)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("prepare: %v", err)
				}
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
				if err != nil {
					t.Fatalf("clone: %v", err)
				}
				t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
				if got := talk(t, h.Endpoint, "ping"); got != "pong" {
					t.Fatalf("ping = %q", got)
				}
				return
			}
			if err == nil {
				t.Fatal("the template warmed, want the warm refused")
			}
			log := zygoteLog(t, rt)
			for _, w := range tc.want {
				if !strings.Contains(log, w) {
					t.Errorf("zygote log lacks %q:\n%s", w, log)
				}
			}
		})
	}
}

// zygoteLog is the one zygote.log under the runtime's run directory.
func zygoteLog(t *testing.T, rt core.Runtime) string {
	t.Helper()
	run := runDirs[rt]
	logs, _ := filepath.Glob(filepath.Join(run, "*", "zygote.log"))
	if len(logs) != 1 {
		t.Fatalf("zygote logs under %s: %v, want one", run, logs)
	}
	b, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
