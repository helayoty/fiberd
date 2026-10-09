// Command summarize reads the JSON lines compare wrote and prints the
// tables: medians over the timed runs of each run's p50 and p99 per
// system and burst, with the cold run discarded, beside setup cost, host
// load, control-plane deltas, resume and density.
//
//	summarize out/*.jsonl
//	summarize -markdown out/*.jsonl    (for a step summary)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/helayoty/fiberd/bench/compare"
	"github.com/helayoty/fiberd/bench/compare/summary"
)

func main() {
	md := flag.Bool("markdown", false, "print a Markdown table")
	flag.Parse()
	var recs []compare.Record
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
		recs = append(recs, rs...)
	}
	rows, sides := summary.Table(recs)
	if *md {
		markdown(os.Stdout, rows, sides)
		return
	}
	summary.Print(os.Stdout, rows, sides)
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
