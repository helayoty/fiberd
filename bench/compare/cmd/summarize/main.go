// Command summarize reads the JSON lines compare wrote and prints the
// tables: medians over the timed runs of each run's p50 and p99 per
// system and burst, with the cold run discarded, beside setup cost, host
// load, control-plane deltas, resume and density.
//
// Files are grouped by their directory, one per phase, and each group
// gets its own tables under a heading. Phases are never merged, since
// phase 1 and phase 2 both have a fiberd-proc row on different hosts.
//
//	summarize bin/compare-state/phase*/*.jsonl
//	summarize -markdown bin/compare-state/phase*/*.jsonl    (for a step summary)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/helayoty/fiberd/bench/compare"
	"github.com/helayoty/fiberd/bench/compare/summary"
)

// phases name the directories the run scripts write.
var phases = map[string]string{
	"phase1": "phase 1, kind shared-kernel",
	"phase2": "phase 2, standalone",
	"phase3": "phase 3, kind sandboxed",
	"phase4": "phase 4, KVM host",
}

func main() {
	md := flag.Bool("markdown", false, "print a Markdown table")
	flag.Parse()
	// Group the files by directory, in the order they came.
	var dirs []string
	recs := map[string][]compare.Record{}
	for _, path := range flag.Args() {
		f, err := os.Open(path)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "summarize:", err)
			os.Exit(1)
		}
		rs, err := summary.Read(f)
		_ = f.Close()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "summarize: %s: %v\n", path, err)
			os.Exit(1)
		}
		dir := filepath.Dir(path)
		if _, ok := recs[dir]; !ok {
			dirs = append(dirs, dir)
		}
		recs[dir] = append(recs[dir], rs...)
	}
	for i, dir := range dirs {
		name := phases[filepath.Base(dir)]
		if name == "" {
			name = dir
		}
		if i > 0 {
			fmt.Println()
		}
		rows, sides := summary.Table(recs[dir])
		if *md {
			fmt.Printf("### %s\n\n", name)
			markdown(os.Stdout, rows, sides)
			continue
		}
		fmt.Printf("== %s\n", name)
		summary.Print(os.Stdout, rows, sides)
	}
}

func markdown(w io.Writer, rows []summary.Row, sides []summary.Side) {
	latency, side := summary.Cells(rows, sides)
	for i, t := range [][][]string{latency, side} {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		for j, row := range t {
			_, _ = fmt.Fprintf(w, "| %s |\n", strings.Join(row, " | "))
			if j == 0 {
				_, _ = fmt.Fprintf(w, "|%s\n", strings.Repeat(" --- |", len(row)))
			}
		}
	}
}
