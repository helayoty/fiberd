package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// A first argument of run is the run subcommand, and anything else is
// fiberd as before. Outcomes map to exit codes. No case here gets as far
// as starting fiberd.
func TestRunSubcommandExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		// out and err are parts of stdout and stderr.
		out, err string
	}{
		{name: "fiberd's own -version", args: []string{"-version"}, code: 0, out: "fiberd "},
		{name: "fiberd's own -h", args: []string{"-h"}, code: 0, err: "-node-id"},
		{name: "bad flag", args: []string{"run", "-nope"}, code: 2, err: "flag provided but not defined"},
		{name: "run help", args: []string{"run", "-h"}, code: 0, err: "-payload"},
		{name: "no template", args: []string{"run"}, code: 1, err: "name the template"},
		{name: "an unknown trust mode", args: []string{"run", "-trust", "signed", "hello.py"}, code: 1, err: `-trust "signed" unknown`},
		{name: "no fibers", args: []string{"run", "-n", "0", "hello.py"}, code: 1, err: "-n 0, want 1 or more"},
		{name: "a negative count", args: []string{"run", "-n", "-2", "hello.py"}, code: 1, err: "-n -2, want 1 or more"},
		{name: "a negative grant", args: []string{"run", "-max", "-1", "hello.py"}, code: 1, err: "-max -1, want 1 or more"},
		{name: "an unknown output", args: []string{"run", "-o", "json", "hello.py"}, code: 1, err: `-o "json" unknown`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tc.args, &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d; stderr %q", code, tc.code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.out) {
				t.Fatalf("stdout %q, want it to hold %q", stdout.String(), tc.out)
			}
			if !strings.Contains(stderr.String(), tc.err) {
				t.Fatalf("stderr %q, want it to hold %q", stderr.String(), tc.err)
			}
		})
	}
}

func TestTemplateCommand(t *testing.T) {
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	cases := []struct {
		name       string
		args       []string
		pythonPath string
		want       []string
		// err is a part of the error, or "" for none.
		err string
	}{
		{name: "a command on PATH stays as given", args: []string{"mytemplate", "--flag"}, want: []string{"mytemplate", "--flag"}},
		{name: "a relative path is made absolute", args: []string{"bin/refzygote", "--heap-mb", "16"},
			want: []string{abs("bin/refzygote"), "--heap-mb", "16"}},
		{name: "a .py file runs under python3", args: []string{"examples/hello/hello.py"},
			want: []string{"python3", abs("examples/hello/hello.py")}},
		{name: "PYTHONPATH is passed on", args: []string{"/srv/hello.py"}, pythonPath: "/src/sdk/python/src",
			want: []string{"env", "PYTHONPATH=/src/sdk/python/src", "python3", "/srv/hello.py"}},
		{name: "no template", err: "name the template"},
		{name: "an argument with a space", args: []string{"mytemplate", "a b"}, err: `argument "a b"`},
		{name: "an empty argument", args: []string{"mytemplate", ""}, err: `argument ""`},
		{name: "a PYTHONPATH with a space", args: []string{"/srv/hello.py"}, pythonPath: "/my src", err: "PYTHONPATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := templateCommand(tc.args, tc.pythonPath)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one holding %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("command %q, want %q", got, tc.want)
			}
		})
	}
}

// runConfig is fiberd on loopback with the proc backend and the template as
// the default, secured as -trust says, and it keeps fiberd's own
// defaults for what run was not told.
func TestRunConfig(t *testing.T) {
	cases := []struct {
		name          string
		state, cgroup string
		trust         string
		wantState     string
		wantCgroup    string
		// err is a part of the error, or "" for none.
		err string
	}{
		{name: "fiberd's defaults", trust: "insecure", wantState: "/var/lib/fiberd", wantCgroup: "/sys/fs/cgroup/fiberd"},
		{name: "a state directory and a cgroup root", trust: "insecure", state: "/tmp/fz1", cgroup: "/sys/fs/cgroup/ci/fz1",
			wantState: "/tmp/fz1", wantCgroup: "/sys/fs/cgroup/ci/fz1"},
		{name: "an unknown trust mode", trust: "signed", err: `-trust "signed" unknown`},
		{name: "no trust mode", err: `-trust "" unknown`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := runConfig(tc.state, tc.cgroup, tc.trust, []string{"python3", "/srv/hello.py"})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one holding %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Node.StateDir != tc.wantState || c.Node.CgroupRoot != tc.wantCgroup {
				t.Fatalf("state %q, cgroup root %q, want %q and %q", c.Node.StateDir, c.Node.CgroupRoot, tc.wantState, tc.wantCgroup)
			}
			if c.Node.ID != runNode || c.API.Listen != "127.0.0.1:0" || !c.API.TLS.InsecurePlaintext ||
				c.Trust.Verifier != "insecure-json" || c.Runtime.Name != "proc" {
				t.Fatalf("config %+v, want node %s on 127.0.0.1:0, plaintext, insecure-json and proc", c, runNode)
			}
			if got := c.Runtime.Templates["default"]; got != "python3 /srv/hello.py" {
				t.Fatalf("default template %q, want %q", got, "python3 /srv/hello.py")
			}
		})
	}
}

// The grant is -n TRUSTED fibers for this home, and the unsigned
// verifier fiberd runs with takes it.
func TestDevGrant(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, n := range []int{1, 3} {
		t.Run(fmt.Sprintf("%d fibers", n), func(t *testing.T) {
			tok, err := devGrant(now, n)
			if err != nil {
				t.Fatal(err)
			}
			g, err := grant.InsecureJSONVerifier{}.Verify(context.Background(), []byte(tok))
			if err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name      string
				got, want any
			}{
				{name: "uid", got: g.UID, want: "hello"},
				{name: "audience", got: g.Audience, want: runNode},
				{name: "fibers", got: g.FiberMax, want: n},
				{name: "isolation", got: g.Policy.Isolation, want: core.Trusted},
				{name: "lease", got: g.LeaseExpiry.Equal(now.Add(10 * time.Minute)), want: true},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if tc.got != tc.want {
						t.Fatalf("%s %v, want %v", tc.name, tc.got, tc.want)
					}
				})
			}
		})
	}
}

// check refuses counts below 1 and lets the grant hold -n fibers when
// -max is not given.
func TestPlanCheck(t *testing.T) {
	cases := []struct {
		name    string
		n, max  int
		wantMax int
		// err is a part of the error, or "" for none.
		err string
	}{
		{name: "one fiber", n: 1, wantMax: 1},
		{name: "max defaults to n", n: 3, wantMax: 3},
		{name: "a grant smaller than n", n: 3, max: 2, wantMax: 2},
		{name: "a grant larger than n", n: 1, max: 4, wantMax: 4},
		{name: "no fibers", n: 0, err: "-n 0"},
		{name: "a negative grant", n: 1, max: -1, err: "-max -1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := plan{n: tc.n, max: tc.max}
			err := o.check()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one holding %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.max != tc.wantMax {
				t.Fatalf("max %d, want %d", o.max, tc.wantMax)
			}
		})
	}
}

// Only a park needs a session to resume.
func TestPlanSession(t *testing.T) {
	cases := []struct {
		name string
		park bool
		i    int
		want string
	}{
		{name: "anonymous without a park", i: 0, want: ""},
		{name: "the first session", park: true, i: 0, want: "s1"},
		{name: "the third session", park: true, i: 2, want: "s3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := plan{park: tc.park}
			if got := o.session(tc.i); got != tc.want {
				t.Fatalf("session %q, want %q", got, tc.want)
			}
		})
	}
}
