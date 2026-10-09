package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/bench/compare"
)

// TestMain runs the command itself when the test re-executes its own
// binary, so the tests read exactly what a phase script prints.
func TestMain(m *testing.M) {
	if os.Getenv("SUMMARIZE_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// phaseRecords writes a cold run and three timed runs of one burst of 1
// for system into dir/system.jsonl.
func phaseRecords(t *testing.T, dir, system string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for run := range 4 {
		line, _ := json.Marshal(compare.Record{Kind: "activation", System: system, Class: "shared-kernel",
			Run: run, Cold: run == 0, Burst: 1, TFirstByteMs: 2})
		b.Write(append(line, '\n'))
	}
	path := filepath.Join(dir, system+".jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPhasesAreNotMerged(t *testing.T) {
	cases := []struct {
		name     string
		markdown bool
		heading  string
	}{
		{name: "text", heading: "== "},
		{name: "markdown", markdown: true, heading: "### "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			args := []string{phaseRecords(t, filepath.Join(root, "phase1"), "fiberd-proc"),
				phaseRecords(t, filepath.Join(root, "phase2"), "fiberd-proc")}
			if tc.markdown {
				args = append([]string{"-markdown"}, args...)
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "SUMMARIZE_MAIN=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			var headings, samples []string
			for _, line := range strings.Split(string(out), "\n") {
				if h, ok := strings.CutPrefix(line, tc.heading); ok {
					headings = append(headings, h)
				}
				if !strings.Contains(line, "fiberd-proc") {
					continue
				}
				f := strings.Fields(strings.ReplaceAll(line, "|", " "))
				samples = append(samples, f[7])
			}
			want := []string{"phase 1, kind shared-kernel", "phase 2, standalone"}
			if strings.Join(headings, ";") != strings.Join(want, ";") {
				t.Errorf("headings %q, want %q\n%s", headings, want, out)
			}
			// One row per phase, three timed runs of one activation each.
			if strings.Join(samples, ",") != "3,3" {
				t.Errorf("fiberd-proc samples %v, want 3 in each phase\n%s", samples, out)
			}
		})
	}
}
