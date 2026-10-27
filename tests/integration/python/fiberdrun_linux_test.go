//go:build linux && integration

package pythontest

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// TestFiberdRunsHello runs the examples/hello templates the way the
// quickstart and the demo do, through fiberd run, and reads what the
// fibers answer and what fiberd run says it did.
func TestFiberdRunsHello(t *testing.T) {
	root := testenv.RepoRoot()
	bin := filepath.Join(t.TempDir(), "fiberd")
	build := exec.Command("go", "build", "-o", bin, "./cmd/fiberd")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fiberd: %v\n%s", err, out)
	}
	hello, counter := "examples/hello/hello.py", "examples/hello/counter.py"
	// A pipe gets raw output, so the raw cases name no -o.
	cases := []struct {
		name     string
		flags    []string
		template string
		// want is stdout whole. rows, when set, instead each match a
		// line of it, since a table holds times.
		want string
		rows []string
		// notes are parts of what fiberd run says on stderr.
		notes []string
	}{
		{name: "no payload", template: hello, want: "hello, world\n"},
		{name: "a payload", flags: []string{"-payload", "fiberd"}, template: hello, want: "hello, fiberd\n"},
		{name: "three fibers from one template", flags: []string{"-n", "3"}, template: hello,
			want: "hello, world\nhello, world\nhello, world\n"},
		{name: "a clone past the grant is refused", flags: []string{"-n", "3", "-max", "2"}, template: hello,
			want:  "hello, world\nhello, world\n",
			notes: []string{"fiberd run: clone 3 refused, the grant holds 2: deferred: ledger: grant at fibers.max, no capacity for a new fiber\n"}},
		{name: "timed clones", flags: []string{"-n", "5", "-time"}, template: hello,
			want:  strings.Repeat("hello, world\n", 5),
			notes: []string{"first clone ", "4 more from the warm template, p50 "}},
		// The count is the fiber's memory, so the resumed fiber goes on
		// from 2.
		{name: "a park keeps the count", flags: []string{"-park"}, template: counter,
			want:  "count 1\ncount 2\ncount 3\n",
			notes: []string{"session s1 parked as hello/1/1, resumed as hello/1/2"}},
		{name: "two sessions parked and resumed, timed", flags: []string{"-n", "2", "-park", "-time"}, template: counter,
			want:  "count 1\ncount 2\ncount 3\ncount 1\ncount 2\ncount 3\n",
			notes: []string{"session s1 parked as hello/1/1 in ", "session s2 parked as hello/1/2 in "}},
		{name: "a table of three fibers", flags: []string{"-o", "table", "-n", "3", "-time"}, template: hello, rows: []string{
			`^fiberd is up\. Cloning 3 fibers from examples/hello/hello\.py\.$`,
			`^  FIBER +EVENT +TIME +SAYS$`,
			`^  hello/1/1 +clone +[0-9.]+ms +hello, world$`,
			`^  hello/1/2 +clone +[0-9.]+ms +hello, world$`,
			`^  hello/1/3 +clone +[0-9.]+ms +hello, world$`,
			`^3 fibers from one template, released\.$`,
			`^The other 2 clones took p50 [0-9.]+ms, p99 [0-9.]+ms\.$`,
		}},
		// examples/fiberd-cli/cli-demo.md quotes these rows.
		{name: "a table of a refusal", flags: []string{"-o", "table", "-n", "3", "-max", "2"}, template: hello, rows: []string{
			`^  - +refused +clone 3, deferred: ledger: grant at fibers\.max, no capacity for a new fiber$`,
			`^2 fibers from one template, released\. 1 clone refused, the grant holds 2\.$`,
		}},
		{name: "a table of a park", flags: []string{"-o", "table", "-park"}, template: counter, rows: []string{
			`^  FIBER +EVENT +SESSION +TIME +SAYS$`,
			`^  hello/1/1 +clone +s1 +[0-9.]+ms +count 1$`,
			`^  hello/1/1 +ask +s1 +count 2$`,
			`^  hello/1/1 +park +s1 +[0-9.]+ms$`,
			`^  hello/1/2 +resume +s1 +[0-9.]+ms +count 3$`,
			`^1 fiber from one template, released\. 1 session parked and resumed\.$`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := filepath.Join(cgRoot, unique("ctl"))
			t.Cleanup(func() { removeTree(cg) })
			args := append([]string{"run", "-cgroup-root", cg}, tc.flags...)
			cmd := exec.Command(bin, append(args, tc.template)...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(root, "sdk", "python", "src"))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("fiberd run: %v\n%s", err, stderr.String())
			}
			got := stdout.String()
			for _, r := range tc.rows {
				if !regexp.MustCompile("(?m)" + r).MatchString(got) {
					t.Fatalf("fiberd run printed\n%s\nwith no line matching %s", got, r)
				}
			}
			if tc.rows == nil && got != tc.want {
				t.Fatalf("fiberd run printed %q, want %q", got, tc.want)
			}
			for _, n := range tc.notes {
				if !strings.Contains(stderr.String(), n) {
					t.Fatalf("fiberd run said %q, want it to hold %q", stderr.String(), n)
				}
			}
		})
	}
}

// removeTree removes the directories under dir, leaves first, as a
// cgroup tree must be removed.
func removeTree(dir string) {
	var dirs []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	slices.Reverse(dirs)
	for _, d := range dirs {
		_ = os.Remove(d)
	}
}
