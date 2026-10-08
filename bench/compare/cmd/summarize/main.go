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
	_, _ = fmt.Fprintln(w, "| class | system | burst | runs | p50 ms | p99 ms | wall ms | samples | errors | probes |")
	_, _ = fmt.Fprintln(w, "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
	for _, r := range rows {
		if r.Samples == 0 {
			_, _ = fmt.Fprintf(w, "| %s | %s | %d | %d | - | - | - | 0 | %d | - |\n", r.Class, r.System, r.Burst, r.Runs, r.Errors)
			continue
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %d | %d | %.2f | %.2f | %.1f | %d | %d | %.0f at %gms |\n",
			r.Class, r.System, r.Burst, r.Runs, r.P50, r.P99, r.Wall, r.Samples, r.Errors, r.Attempts, r.PollMs)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| class | system | setup ms | load first | load last | resume ms | density, deltas |")
	_, _ = fmt.Fprintln(w, "| --- | --- | ---: | --- | --- | ---: | --- |")
	for _, s := range sides {
		res := fmt.Sprintf("%.2f", s.ResumeMs)
		if s.ResumeErr != "" {
			res = "n/a"
		}
		extra := ""
		if s.DensityN > 0 {
			extra = fmt.Sprintf("n=%d marginal=%.1fMiB amortized=%.1fMiB", s.DensityN, float64(s.Marginal)/(1<<20), float64(s.Amortized)/(1<<20))
		}
		for name, v := range s.Deltas {
			extra += fmt.Sprintf(" %s=%g", name, v)
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %.0f | %s | %s | %s | %s |\n", s.Class, s.System, s.SetupMs, s.LoadFirst, s.LoadLast, res, extra)
	}
}
