package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/bench/compare"
)

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
			var out, stderr bytes.Buffer
			if err := run(args, &out, &stderr); err != nil {
				t.Fatalf("%v: %s", err, stderr.String())
			}
			var headings, samples []string
			for _, line := range strings.Split(out.String(), "\n") {
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
				t.Errorf("headings %q, want %q\n%s", headings, want, out.String())
			}
			// One row per phase, three timed runs of one activation each.
			if strings.Join(samples, ",") != "3,3" {
				t.Errorf("fiberd-proc samples %v, want 3 in each phase\n%s", samples, out.String())
			}
		})
	}
}

// TestRunRefuses covers what run reports instead of printing a table.
func TestRunRefuses(t *testing.T) {
	cases := []struct {
		name string
		args func(root string) []string
		want string
	}{
		{name: "a file that is not there", args: func(root string) []string { return []string{filepath.Join(root, "nope.jsonl")} }, want: "no such file"},
		{name: "a file that is not records", args: func(root string) []string {
			path := filepath.Join(root, "bad.jsonl")
			if err := os.WriteFile(path, []byte("not json\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{path}
		}, want: "bad.jsonl"},
		{name: "a flag it does not know", args: func(string) []string { return []string{"-bogus"} }, want: "flag provided but not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			err := run(tc.args(t.TempDir()), &out, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want an error naming %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("printed %q on failure", out.String())
			}
		})
	}
}
