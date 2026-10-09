// Package summary turns the JSON lines the client wrote into the table
// docs/design/compare.md asks for: per system and burst size, the median
// over the timed runs of each run's p50 and p99, with the cold run
// discarded and errors counted apart. Setup cost, host load,
// control-plane deltas, resume and density are listed beside it.
package summary

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/helayoty/fiberd/bench/compare"
)

// Read parses JSON lines. Blank lines are skipped and a bad line is an
// error, since a truncated file must not silently thin a table.
func Read(r io.Reader) ([]compare.Record, error) {
	var recs []compare.Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec compare.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		recs = append(recs, rec)
	}
	return recs, sc.Err()
}

// Row is one line of the latency table.
type Row struct {
	System, Class string
	Burst         int
	// Runs is how many timed runs had at least one good activation.
	Runs int
	// P50 and P99 are medians over runs of each run's quantile, in ms.
	P50, P99 float64
	// Wall is the median burst wall time over runs, in ms.
	Wall float64
	// Samples is the good activations over all timed runs. Errors is the
	// failed ones, cold run included so a broken setup is visible.
	Samples, Errors int
	// Attempts is the median number of probes that got no reply, and
	// PollMs the interval. Zero attempts means the first request was the
	// measurement.
	Attempts float64
	PollMs   float64
}

// Side is everything that is not an activation latency, per system.
type Side struct {
	System, Class string
	SetupMs       float64
	// Load is the host load before the first and after the last run.
	LoadFirst, LoadLast string
	// Deltas are the control-plane counters per timed run, medianed.
	Deltas map[string]float64
	// ResumeMs is the median resume to first byte over the timed runs,
	// 0 when unsupported. The cold run is discarded, errors and all.
	ResumeMs  float64
	ResumeErr string
	// Density, bytes per idle instance, medians over the timed runs.
	// Marginal is the instances' own charge over N, Amortized adds what
	// the system keeps standing.
	DensityN   int
	Marginal   int64
	Amortized  int64
	DensityErr string
}

type key struct {
	system, class string
	burst         int
}

// Table groups activation records into rows and side information.
func Table(recs []compare.Record) ([]Row, []Side) {
	byRun := map[key]map[int][]float64{} // run -> good latencies
	walls := map[key]map[int]float64{}
	attempts := map[key][]float64{}
	errs := map[key]int{}
	poll := map[key]float64{}
	sides := map[[2]string]*Side{}
	resume := map[[2]string][]float64{}
	density := map[[2]string]*[3][]float64{} // n, marginal, amortized per run
	side := func(r compare.Record) *Side {
		k := [2]string{r.System, r.Class}
		if sides[k] == nil {
			sides[k] = &Side{System: r.System, Class: r.Class, Deltas: map[string]float64{}}
		}
		return sides[k]
	}
	deltas := map[[2]string]map[string][]float64{}
	for _, r := range recs {
		k := key{r.System, r.Class, r.Burst}
		switch r.Kind {
		case "activation":
			if r.Error != "" {
				errs[k]++
				continue
			}
			if r.Cold {
				continue
			}
			if byRun[k] == nil {
				byRun[k] = map[int][]float64{}
			}
			byRun[k][r.Run] = append(byRun[k][r.Run], r.TFirstByteMs)
			attempts[k] = append(attempts[k], float64(r.Attempts))
			poll[k] = r.PollMs
		case "burst":
			if r.Cold {
				continue
			}
			if walls[k] == nil {
				walls[k] = map[int]float64{}
			}
			walls[k][r.Run] = r.WallMs
		case "setup":
			side(r).SetupMs = r.SetupMs
		case "run":
			s := side(r)
			if s.LoadFirst == "" {
				s.LoadFirst = r.LoadBefore
			}
			s.LoadLast = r.LoadAfter
			if r.Cold {
				continue
			}
			sk := [2]string{r.System, r.Class}
			if deltas[sk] == nil {
				deltas[sk] = map[string][]float64{}
			}
			for name, v := range r.Deltas {
				deltas[sk][name] = append(deltas[sk][name], v)
			}
		case "resume":
			if r.Cold {
				continue
			}
			s := side(r)
			if r.Error != "" {
				s.ResumeErr = r.Error
				continue
			}
			resume[[2]string{r.System, r.Class}] = append(resume[[2]string{r.System, r.Class}], r.TFirstByteMs)
		case "density":
			if r.Cold {
				continue
			}
			s := side(r)
			if r.Error != "" {
				s.DensityErr = r.Error
				continue
			}
			if r.N == 0 {
				continue
			}
			sk := [2]string{r.System, r.Class}
			if density[sk] == nil {
				density[sk] = &[3][]float64{}
			}
			d := density[sk]
			d[0] = append(d[0], float64(r.N))
			d[1] = append(d[1], float64(r.Bytes/int64(r.N)))
			d[2] = append(d[2], float64((r.Bytes+r.Standing)/int64(r.N)))
		}
	}
	var rows []Row
	for k, runs := range byRun {
		row := Row{System: k.system, Class: k.class, Burst: k.burst, Errors: errs[k], PollMs: poll[k]}
		var p50s, p99s, ws []float64
		for run, lat := range runs {
			row.Samples += len(lat)
			p50s = append(p50s, Quantile(lat, 0.50))
			p99s = append(p99s, Quantile(lat, 0.99))
			if w, ok := walls[k][run]; ok {
				ws = append(ws, w)
			}
		}
		row.Runs = len(runs)
		row.P50, row.P99, row.Wall = Median(p50s), Median(p99s), Median(ws)
		row.Attempts = Median(attempts[k])
		rows = append(rows, row)
	}
	// Bursts that only ever failed still get a row, so the table says so.
	for k, n := range errs {
		if _, ok := byRun[k]; !ok && k.burst > 0 {
			rows = append(rows, Row{System: k.system, Class: k.class, Burst: k.burst, Errors: n})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.System != b.System {
			return a.System < b.System
		}
		return a.Burst < b.Burst
	})
	var out []Side
	for sk, s := range sides {
		for name, vs := range deltas[sk] {
			s.Deltas[name] = Median(vs)
		}
		s.ResumeMs = Median(resume[sk])
		if d := density[sk]; d != nil {
			s.DensityN, s.Marginal, s.Amortized = int(Median(d[0])), int64(Median(d[1])), int64(Median(d[2]))
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].System < out[j].System
	})
	return rows, out
}

// Quantile is the nearest-rank quantile of xs. Empty gives 0.
func Quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(q*float64(len(s))+0.999999) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

// Median is the middle value, the mean of the two middle ones for an
// even count. Empty gives 0.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Cells lays the two tables out as rows of cells, headers first, for
// Print and for a Markdown table. Each control-plane counter is a column
// of its own, in name order.
func Cells(rows []Row, sides []Side) (latency, side [][]string) {
	latency = [][]string{{"class", "system", "burst", "runs", "p50 ms", "p99 ms", "wall ms", "samples", "errors", "probes"}}
	for _, r := range rows {
		if r.Samples == 0 {
			latency = append(latency, []string{r.Class, r.System, fmt.Sprint(r.Burst), fmt.Sprint(r.Runs), "-", "-", "-", "0", fmt.Sprint(r.Errors), "-"})
			continue
		}
		latency = append(latency, []string{r.Class, r.System, fmt.Sprint(r.Burst), fmt.Sprint(r.Runs),
			fmt.Sprintf("%.2f", r.P50), fmt.Sprintf("%.2f", r.P99), fmt.Sprintf("%.1f", r.Wall), fmt.Sprint(r.Samples),
			fmt.Sprint(r.Errors), fmt.Sprintf("%.0f@%gms", r.Attempts, r.PollMs)})
	}
	var names []string
	seen := map[string]bool{}
	for _, sd := range sides {
		for n := range sd.Deltas {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	head := []string{"class", "system", "setup ms", "load first", "load last", "resume ms", "density n", "marginal", "amortized"}
	side = [][]string{append(append(head, names...), "note")}
	for _, sd := range sides {
		res, n, marg, amort := fmt.Sprintf("%.2f", sd.ResumeMs), "-", "-", "-"
		if sd.ResumeErr != "" {
			res = "n/a"
		}
		if sd.DensityN > 0 {
			n, marg, amort = fmt.Sprint(sd.DensityN), mib(sd.Marginal), mib(sd.Amortized)
		}
		row := []string{sd.Class, sd.System, fmt.Sprintf("%.0f", sd.SetupMs), sd.LoadFirst, sd.LoadLast, res, n, marg, amort}
		for _, name := range names {
			v, ok := sd.Deltas[name]
			if !ok {
				row = append(row, "-")
				continue
			}
			row = append(row, fmt.Sprintf("%g", v))
		}
		var notes []string
		if sd.ResumeErr != "" {
			notes = append(notes, "resume: "+sd.ResumeErr)
		}
		if sd.DensityErr != "" {
			notes = append(notes, "density: "+sd.DensityErr)
		}
		side = append(side, append(row, strings.Join(notes, "; ")))
	}
	return latency, side
}

// Print writes the tables as aligned text.
func Print(w io.Writer, rows []Row, sides []Side) {
	latency, side := Cells(rows, sides)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, t := range [][][]string{latency, side} {
		if i > 0 {
			_, _ = fmt.Fprintln(tw)
		}
		for _, row := range t {
			_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
	}
	_ = tw.Flush()
}

func mib(b int64) string { return fmt.Sprintf("%.1fMiB", float64(b)/(1<<20)) }
