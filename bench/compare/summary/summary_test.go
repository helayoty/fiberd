package summary

import (
	"bytes"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/bench/compare"
)

func act(run, burst int, ms float64, err string) compare.Record {
	return compare.Record{Kind: "activation", System: "s", Class: "c", Run: run, Cold: run == 0, Burst: burst, TFirstByteMs: ms, Error: err, PollMs: 1}
}

func TestTable(t *testing.T) {
	cases := []struct {
		name     string
		recs     []compare.Record
		wantRows int
		wantP50  float64
		wantP99  float64
		wantErr  int
		wantSamp int
		wantRuns int
		wantSide func(t *testing.T, s Side)
	}{
		{
			name: "cold run discarded, medians over runs of each run's quantile",
			recs: []compare.Record{
				act(0, 1, 900, ""),                                      // cold, ignored
				act(1, 1, 10, ""), act(1, 1, 20, ""), act(1, 1, 30, ""), // p50 20, p99 30
				act(2, 1, 100, ""), act(2, 1, 200, ""), act(2, 1, 300, ""), // p50 200, p99 300
				act(3, 1, 1, ""), act(3, 1, 2, ""), act(3, 1, 3, ""), // p50 2, p99 3
			},
			wantRows: 1, wantP50: 20, wantP99: 30, wantSamp: 9, wantRuns: 3,
		},
		{
			name:     "errors counted apart, cold errors included",
			recs:     []compare.Record{act(0, 1, 0, "boom"), act(1, 1, 5, ""), act(1, 1, 0, "boom")},
			wantRows: 1, wantP50: 5, wantP99: 5, wantErr: 2, wantSamp: 1, wantRuns: 1,
		},
		{
			name:     "a burst that only failed still has a row",
			recs:     []compare.Record{act(1, 10, 0, "boom"), act(2, 10, 0, "boom")},
			wantRows: 1, wantErr: 2,
		},
		{
			name: "side information",
			recs: []compare.Record{
				{Kind: "setup", System: "s", Class: "c", SetupMs: 1500},
				{Kind: "run", System: "s", Class: "c", Run: 0, Cold: true, LoadBefore: "9 9 9", LoadAfter: "8 8 8", Deltas: map[string]float64{"w": 99}},
				{Kind: "run", System: "s", Class: "c", Run: 1, LoadBefore: "2 2 2", LoadAfter: "3 3 3", Deltas: map[string]float64{"w": 4}},
				{Kind: "run", System: "s", Class: "c", Run: 2, LoadAfter: "4 4 4", Deltas: map[string]float64{"w": 6}},
				{Kind: "resume", System: "s", Class: "c", Run: 1, TFirstByteMs: 12},
				{Kind: "resume", System: "s", Class: "c", Run: 2, TFirstByteMs: 14},
				{Kind: "density", System: "s", Class: "c", Run: 1, N: 4, Bytes: 4 << 20, Standing: 8 << 20},
				act(1, 1, 1, ""),
			},
			wantRows: 1, wantP50: 1, wantP99: 1, wantSamp: 1, wantRuns: 1,
			wantSide: func(t *testing.T, s Side) {
				if s.SetupMs != 1500 || s.LoadFirst != "9 9 9" || s.LoadLast != "4 4 4" {
					t.Errorf("setup/load %+v", s)
				}
				if s.Deltas["w"] != 5 {
					t.Errorf("delta median %v, want 5 (cold run excluded)", s.Deltas["w"])
				}
				if s.ResumeMs != 13 {
					t.Errorf("resume %v, want 13", s.ResumeMs)
				}
				if s.DensityN != 4 || s.Marginal != 1<<20 || s.Amortized != 3<<20 {
					t.Errorf("density %+v", s)
				}
			},
		},
		{
			name: "hold lines are not latency samples",
			recs: []compare.Record{
				{Kind: "hold", System: "s", Class: "c", Run: 1, TFirstByteMs: 500},
				act(1, 1, 1, ""),
			},
			wantRows: 1, wantP50: 1, wantP99: 1, wantSamp: 1, wantRuns: 1,
		},
		{
			name: "the cold run's resume error is discarded with the cold run",
			recs: []compare.Record{
				{Kind: "resume", System: "s", Class: "c", Run: 0, Cold: true, Error: "resume: boom"},
				{Kind: "resume", System: "s", Class: "c", Run: 1, TFirstByteMs: 12},
				act(1, 1, 1, ""),
			},
			wantRows: 1, wantP50: 1, wantP99: 1, wantSamp: 1, wantRuns: 1,
			wantSide: func(t *testing.T, s Side) {
				if s.ResumeErr != "" || s.ResumeMs != 12 {
					t.Errorf("resume %q %v, want no error and 12", s.ResumeErr, s.ResumeMs)
				}
			},
		},
		{
			name: "density is the median over the timed runs, not the last run",
			recs: []compare.Record{
				{Kind: "density", System: "s", Class: "c", Run: 0, Cold: true, N: 4, Bytes: 400 << 20, Standing: 8 << 20},
				{Kind: "density", System: "s", Class: "c", Run: 1, N: 4, Bytes: 4 << 20, Standing: 8 << 20},
				{Kind: "density", System: "s", Class: "c", Run: 2, N: 4, Bytes: 8 << 20, Standing: 8 << 20},
				{Kind: "density", System: "s", Class: "c", Run: 3, N: 4, Bytes: 40 << 20, Standing: 8 << 20},
				act(1, 1, 1, ""),
			},
			wantRows: 1, wantP50: 1, wantP99: 1, wantSamp: 1, wantRuns: 1,
			wantSide: func(t *testing.T, s Side) {
				if s.DensityN != 4 || s.Marginal != 2<<20 || s.Amortized != 4<<20 {
					t.Errorf("density n=%d marginal=%d amortized=%d, want 4, 2MiB, 4MiB", s.DensityN, s.Marginal, s.Amortized)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, sides := Table(tc.recs)
			if len(rows) != tc.wantRows {
				t.Fatalf("rows %d, want %d: %+v", len(rows), tc.wantRows, rows)
			}
			r := rows[0]
			if r.P50 != tc.wantP50 || r.P99 != tc.wantP99 || r.Errors != tc.wantErr || r.Samples != tc.wantSamp || r.Runs != tc.wantRuns {
				t.Errorf("row %+v", r)
			}
			if tc.wantSide != nil {
				if len(sides) != 1 {
					t.Fatalf("sides %+v", sides)
				}
				tc.wantSide(t, sides[0])
			}
			var out bytes.Buffer
			Print(&out, rows, sides)
			if !strings.Contains(out.String(), "p50 ms") {
				t.Error("Print wrote no header")
			}
		})
	}
}

func TestQuantileMedian(t *testing.T) {
	cases := []struct {
		name   string
		xs     []float64
		q      float64
		wantQ  float64
		wantMd float64
	}{
		{name: "empty", wantQ: 0, wantMd: 0},
		{name: "one", xs: []float64{7}, q: 0.99, wantQ: 7, wantMd: 7},
		{name: "odd count p50 is the middle", xs: []float64{3, 1, 2}, q: 0.5, wantQ: 2, wantMd: 2},
		{name: "even count median averages", xs: []float64{4, 1, 3, 2}, q: 0.5, wantQ: 2, wantMd: 2.5},
		{name: "p99 of 100 is the 99th", xs: seq(100), q: 0.99, wantQ: 99, wantMd: 50.5},
		{name: "p99 of 10 is the last", xs: seq(10), q: 0.99, wantQ: 10, wantMd: 5.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Quantile(tc.xs, tc.q); got != tc.wantQ {
				t.Errorf("quantile %v, want %v", got, tc.wantQ)
			}
			if got := Median(tc.xs); got != tc.wantMd {
				t.Errorf("median %v, want %v", got, tc.wantMd)
			}
		})
	}
}

func seq(n int) []float64 {
	xs := make([]float64, n)
	for i := range xs {
		xs[i] = float64(i + 1)
	}
	return xs
}

func TestRead(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{name: "lines and blanks", in: "{\"kind\":\"setup\"}\n\n{\"kind\":\"run\"}\n", want: 2},
		{name: "truncated line is an error", in: "{\"kind\":\"setup\"}\n{\"kind\":", wantErr: true},
		{name: "empty", in: "", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := Read(strings.NewReader(tc.in))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, want error %v", err, tc.wantErr)
			}
			if len(recs) != tc.want {
				t.Errorf("records %d, want %d", len(recs), tc.want)
			}
		})
	}
}

func TestPrintAligns(t *testing.T) {
	deltas := map[string]float64{"apiserver_objects": 577, "apiserver_writes": 2483, "audit_events": 2862, "scheduler_attempts": 0}
	cases := []struct {
		name  string
		rows  []Row
		sides []Side
		cells [][]string // each printed line's cells, header first, as the table shows them
	}{
		{name: "a long class, three-number loads, deltas and a note",
			rows: []Row{{Class: "shared-kernel", System: "agentsandbox-runc-pool1", Burst: 50, Runs: 3, P50: 1011.58, P99: 1300.2, Wall: 1500, Samples: 150, Errors: 0, Attempts: 12, PollMs: 1}},
			sides: []Side{
				{Class: "shared-kernel", System: "agentsandbox-runc-pool10", SetupMs: 1018, LoadFirst: "3.87 8.39 7.30", LoadLast: "8.40 9.14 7.82", Deltas: deltas, DensityErr: "no cgroup under /host/sys/fs/cgroup for dbffee01"},
				{Class: "shared-kernel", System: "fiberd-proc", SetupMs: 51, LoadFirst: "3.65 8.44 6.40", LoadLast: "4.08 8.45 6.41", ResumeMs: 33.03, Deltas: deltas, DensityN: 20, Marginal: 1 << 19, Amortized: 1 << 19},
			},
			cells: [][]string{
				{"class", "system", "burst", "runs", "p50 ms", "p99 ms", "wall ms", "samples", "errors", "probes"},
				{"shared-kernel", "agentsandbox-runc-pool1", "50", "3", "1011.58", "1300.20", "1500.0", "150", "0", "12@1ms"},
				{"class", "system", "setup ms", "load first", "load last", "resume ms", "density n", "marginal", "amortized", "apiserver_objects", "apiserver_writes", "audit_events", "scheduler_attempts", "note"},
				{"shared-kernel", "agentsandbox-runc-pool10", "1018", "3.87 8.39 7.30", "8.40 9.14 7.82", "0.00", "-", "-", "-", "577", "2483", "2862", "0", "density: no cgroup"},
				{"shared-kernel", "fiberd-proc", "51", "3.65 8.44 6.40", "4.08 8.45 6.41", "33.03", "20", "0.5MiB", "0.5MiB", "577", "2483", "2862", "0"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			Print(&out, tc.rows, tc.sides)
			var lines []string
			for _, l := range strings.Split(out.String(), "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, l)
				}
			}
			if len(lines) != len(tc.cells) {
				t.Fatalf("%d lines, want %d:\n%s", len(lines), len(tc.cells), out.String())
			}
			// Every cell of a table starts where its header does.
			var starts []int
			for i, cells := range tc.cells {
				pos, at := make([]int, len(cells)), 0
				for k, c := range cells {
					j := strings.Index(lines[i][at:], c)
					if j < 0 {
						t.Fatalf("line %d has no %q after column %d:\n%s", i, c, at, out.String())
					}
					pos[k], at = at+j, at+j+len(c)
				}
				if cells[0] == "class" {
					starts = pos
					continue
				}
				for k := range pos {
					if pos[k] != starts[k] {
						t.Fatalf("line %d: %q starts at %d, its header at %d:\n%s", i, cells[k], pos[k], starts[k], out.String())
					}
				}
			}
		})
	}
}
