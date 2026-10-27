package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// sp is n spaces, so the expected rows below show their padding.
func sp(n int) string { return strings.Repeat(" ", n) }

// A run of two fibers, the third clone refused, as the table shows it.
// The columns are two spaces in, then FIBER 12 wide, EVENT 8 and TIME 9,
// each followed by one space, and SESSION 8 when a park is shown.
func TestTableView(t *testing.T) {
	msec := time.Millisecond
	cases := []struct {
		name  string
		park  bool
		timed bool
		run   func(v view)
		want  string
	}{
		{name: "clones and a refusal, timed", timed: true, run: func(v view) {
			v.start("examples/hello/hello.py", 3)
			v.step(step{fiber: "hello/1/1", event: eventClone, took: 412 * msec, says: []byte("hello, world\n")})
			v.step(step{fiber: "hello/1/2", event: eventClone, took: 2 * msec, says: []byte("hello, world\n")})
			v.refused(refusal{clone: 3, max: 2, err: errors.New("deferred: grant full")})
			v.end(summary{fibers: 2, refused: 1, max: 2, took: []time.Duration{412 * msec, 2 * msec}})
		}, want: "fiberd is up. Cloning 3 fibers from examples/hello/hello.py.\n\n" +
			"  FIBER" + sp(8) + "EVENT" + sp(4) + "TIME" + sp(6) + "SAYS\n" +
			"  hello/1/1" + sp(4) + "clone" + sp(4) + "412.0ms" + sp(3) + "hello, world\n" +
			"  hello/1/2" + sp(4) + "clone" + sp(4) + "2.0ms" + sp(5) + "hello, world\n" +
			"  -" + sp(12) + "refused" + sp(12) + "clone 3, deferred: grant full\n" +
			"\n2 fibers from one template, released. 1 clone refused, the grant holds 2.\n" +
			"The first clone's time includes warming the template.\n" +
			"The other clone took 2.0ms.\n"},
		{name: "a park and resume", park: true, run: func(v view) {
			v.start("examples/hello/counter.py", 1)
			v.step(step{fiber: "hello/1/1", event: eventClone, session: "s1", took: 410 * msec, says: []byte("count 1\n")})
			v.step(step{fiber: "hello/1/1", event: eventAsk, session: "s1", says: []byte("count 2\n")})
			v.step(step{fiber: "hello/1/1", event: eventPark, session: "s1", took: 38 * msec})
			v.step(step{fiber: "hello/1/2", event: eventResume, session: "s1", took: 24 * msec, says: []byte("count 3\n")})
			v.end(summary{fibers: 1, max: 1, parked: 1, took: []time.Duration{410 * msec}})
		}, want: "fiberd is up. Cloning 1 fiber from examples/hello/counter.py.\n\n" +
			"  FIBER" + sp(8) + "EVENT" + sp(4) + "SESSION" + sp(2) + "TIME" + sp(6) + "SAYS\n" +
			"  hello/1/1" + sp(4) + "clone" + sp(4) + "s1" + sp(7) + "410.0ms" + sp(3) + "count 1\n" +
			"  hello/1/1" + sp(4) + "ask" + sp(6) + "s1" + sp(17) + "count 2\n" +
			"  hello/1/1" + sp(4) + "park" + sp(5) + "s1" + sp(7) + "38.0ms\n" +
			"  hello/1/2" + sp(4) + "resume" + sp(3) + "s1" + sp(7) + "24.0ms" + sp(4) + "count 3\n" +
			"\n1 fiber from one template, released. 1 session parked and resumed.\n" +
			"The first clone's time includes warming the template.\n"},
		{name: "many clones, timed", timed: true, run: func(v view) {
			v.end(summary{fibers: 3, max: 3, took: []time.Duration{400 * msec, 2 * msec, 4 * msec}})
		}, want: "\n3 fibers from one template, released.\n" +
			"The first clone's time includes warming the template.\n" +
			"The other 2 clones took p50 2.0ms, p99 4.0ms.\n"},
		{name: "many clones, untimed", run: func(v view) {
			v.end(summary{fibers: 3, max: 3, took: []time.Duration{400 * msec, 2 * msec, 4 * msec}})
		}, want: "\n3 fibers from one template, released.\n" +
			"The first clone's time includes warming the template.\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			tc.run(&tableView{w: &b, park: tc.park, timed: tc.timed})
			if got := b.String(); got != tc.want {
				t.Fatalf("table\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// raw passes the fibers' bytes through untouched and says the rest on
// notes.
func TestRawView(t *testing.T) {
	msec := time.Millisecond
	cases := []struct {
		name             string
		timed            bool
		wantOut, wantSay string
	}{
		{name: "untimed", wantOut: "count 1\ncount 2\ncount 3\n",
			wantSay: "fiberd run: session s1 parked as hello/1/1, resumed as hello/1/2\n" +
				"fiberd run: clone 2 refused, the grant holds 1: deferred: grant full\n"},
		{name: "timed", timed: true, wantOut: "count 1\ncount 2\ncount 3\n",
			wantSay: "fiberd run: session s1 parked as hello/1/1 in 38.0ms, resumed as hello/1/2 in 24.0ms\n" +
				"fiberd run: clone 2 refused, the grant holds 1: deferred: grant full\n" +
				"fiberd run: first clone 410.0ms, with the template's warm-up\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, notes bytes.Buffer
			v := &rawView{out: &out, notes: &notes, timed: tc.timed}
			v.start("examples/hello/counter.py", 2)
			v.step(step{fiber: "hello/1/1", event: eventClone, session: "s1", took: 410 * msec, says: []byte("count 1\n")})
			v.step(step{fiber: "hello/1/1", event: eventAsk, session: "s1", says: []byte("count 2\n")})
			v.step(step{fiber: "hello/1/1", event: eventPark, session: "s1", took: 38 * msec})
			v.step(step{fiber: "hello/1/2", event: eventResume, session: "s1", took: 24 * msec, says: []byte("count 3\n")})
			v.refused(refusal{clone: 2, max: 1, err: errors.New("deferred: grant full")})
			v.end(summary{fibers: 1, refused: 1, max: 1, parked: 1, took: []time.Duration{410 * msec}})
			if out.String() != tc.wantOut {
				t.Fatalf("stdout %q, want %q", out.String(), tc.wantOut)
			}
			if notes.String() != tc.wantSay {
				t.Fatalf("notes %q, want %q", notes.String(), tc.wantSay)
			}
		})
	}
}

// -o picks the view. auto is raw here, since a buffer is no terminal.
func TestNewView(t *testing.T) {
	cases := []struct {
		mode string
		want string
		// err is a part of the error, or "" for none.
		err string
	}{
		{mode: "auto", want: "raw"},
		{mode: "table", want: "table"},
		{mode: "raw", want: "raw"},
		{mode: "json", err: `-o "json" unknown`},
		{mode: "", err: `-o "" unknown`},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			var b bytes.Buffer
			v, err := newView(tc.mode, &b, &b, false, false)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one holding %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := "raw"
			if _, ok := v.(*tableView); ok {
				got = "table"
			}
			if got != tc.want {
				t.Fatalf("-o %s is %s, want %s", tc.mode, got, tc.want)
			}
		})
	}
}

func TestSays(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{name: "one line", in: []byte("hello, world\n"), want: "hello, world"},
		{name: "no newline", in: []byte("count 3"), want: "count 3"},
		{name: "two lines", in: []byte("a\nb\n"), want: "a / b"},
		{name: "nothing", in: nil, want: ""},
		{name: "not text", in: []byte{0xff, 0xfe, 0x00}, want: "(3 bytes)"},
		// A fiber's answer must not drive the operator's terminal.
		{name: "an escape sequence", in: []byte("\x1b[2Jhi\n"), want: "�[2Jhi"},
		{name: "a carriage return", in: []byte("a\rb"), want: "a�b"},
		{name: "a tab", in: []byte("a\tb"), want: "a b"},
		{name: "text beyond ASCII", in: []byte("héllo, 世界"), want: "héllo, 世界"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := says(tc.in); got != tc.want {
				t.Fatalf("says %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCount(t *testing.T) {
	cases := []struct {
		n     int
		thing string
		want  string
	}{
		{n: 1, thing: "fiber", want: "1 fiber"},
		{n: 0, thing: "fiber", want: "0 fibers"},
		{n: 3, thing: "session", want: "3 sessions"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := count(tc.n, tc.thing); got != tc.want {
				t.Fatalf("count %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPercentile(t *testing.T) {
	hundred := make([]time.Duration, 100)
	for i := range hundred {
		hundred[len(hundred)-1-i] = time.Duration(i+1) * time.Millisecond // descending, to prove the sort
	}
	cases := []struct {
		name string
		ds   []time.Duration
		q    float64
		want time.Duration
	}{
		{name: "one value", ds: []time.Duration{5 * time.Millisecond}, q: 0.99, want: 5 * time.Millisecond},
		{name: "p50 of 100", ds: hundred, q: 0.50, want: 50 * time.Millisecond},
		{name: "p99 of 100", ds: hundred, q: 0.99, want: 99 * time.Millisecond},
		{name: "p50 of an even pair is the lower", ds: []time.Duration{2, 1}, q: 0.50, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.ds)
			if got := percentile(tc.ds, tc.q); got != tc.want {
				t.Fatalf("percentile %v, want %v", got, tc.want)
			}
			if !slices.Equal(tc.ds, before) {
				t.Fatal("percentile reordered its input")
			}
		})
	}
}

// The first clone also warmed the template, so it is shown apart.
func TestReport(t *testing.T) {
	msec := time.Millisecond
	cases := []struct {
		name string
		took []time.Duration
		want string
	}{
		{name: "nothing cloned", want: ""},
		{name: "one clone", took: []time.Duration{180 * msec},
			want: "fiberd run: first clone 180.0ms, with the template's warm-up\n"},
		{name: "three clones", took: []time.Duration{180 * msec, 2 * msec, 4 * msec},
			want: "fiberd run: first clone 180.0ms, with the template's warm-up\n" +
				"fiberd run: 2 more from the warm template, p50 2.0ms, p99 4.0ms\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			report(&b, tc.took)
			if got := b.String(); got != tc.want {
				t.Fatalf("report %q, want %q", got, tc.want)
			}
		})
	}
}

// Only a terminal gets the table under -o auto. The null device is a
// character device too, but output sent there is not read.
func TestTerminal(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = null.Close() })
	file, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	cases := []struct {
		name string
		w    io.Writer
	}{
		{name: "a buffer", w: &bytes.Buffer{}},
		{name: "a regular file", w: file},
		{name: "the null device", w: null},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if terminal(tc.w) {
				t.Fatalf("%s counts as a terminal", tc.name)
			}
		})
	}
}
