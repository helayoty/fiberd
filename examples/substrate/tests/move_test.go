package substratetest

import (
	"testing"
	"time"
)

// TestMoveLine pins the record's format, which docs/benchmarks.md and
// the demo's generator read. Change it only with them.
func TestMoveLine(t *testing.T) {
	cases := []struct {
		name                       string
		side, backend, actor, from string
		to                         string
		ready                      time.Duration
		count                      string
		kept                       bool
		want                       string
	}{
		{name: "fiberd restores on the other worker with the count it parked with",
			side: "fiberd", backend: "gvisor", actor: "x1", from: "x1", to: "worker-a", ready: 414 * time.Millisecond, count: "3", kept: true,
			want: "move: side=fiberd backend=gvisor actor=x1 from=x1 to=worker-a ready=414ms count=3 state=kept"},
		{name: "a plain process starts empty",
			side: "plain", backend: "proc", actor: "-", from: "-", to: "worker-b", ready: 180 * time.Millisecond, count: "0",
			want: "move: side=plain backend=proc actor=- from=- to=worker-b ready=180ms count=0 state=lost"},
		{name: "rounded to the millisecond",
			side: "plain", backend: "proc", actor: "-", from: "-", to: "worker-b", ready: 1234567 * time.Microsecond, count: "0",
			want: "move: side=plain backend=proc actor=- from=- to=worker-b ready=1.235s count=0 state=lost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := moveLine(tc.side, tc.backend, tc.actor, tc.from, tc.to, tc.ready, tc.count, tc.kept); got != tc.want {
				t.Fatalf("moveLine =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}
