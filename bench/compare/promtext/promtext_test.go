package promtext

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const page = `# HELP apiserver_request_total Counter of apiserver requests
# TYPE apiserver_request_total counter
apiserver_request_total{code="201",verb="POST",resource="pods"} 10
apiserver_request_total{code="200",verb="GET",resource="pods"} 500
apiserver_request_total{code="200",verb="PATCH",resource="pods"} 2.5
apiserver_request_total_bucket{le="1"} 999
apiserver_storage_objects{resource="pods"} 42
apiserver_storage_objects{resource="secrets"} 8
scheduler_schedule_attempts_total{profile="default-scheduler",result="scheduled"} 7 1700000000000
`

func TestSum(t *testing.T) {
	cases := []struct {
		name   string
		metric string
		keep   func(map[string]string) bool
		want   float64
	}{
		{name: "writes only", metric: "apiserver_request_total", keep: Writes, want: 12.5},
		{name: "every sample, longer names skipped", metric: "apiserver_request_total", want: 512.5},
		{name: "objects", metric: "apiserver_storage_objects", want: 50},
		{name: "sample with a timestamp", metric: "scheduler_schedule_attempts_total", want: 7},
		{name: "unknown metric", metric: "nothing_here", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sum(page, tc.metric, tc.keep); got != tc.want {
				t.Errorf("sum %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSampler(t *testing.T) {
	cases := []struct {
		name  string
		reads []float64
		want  []map[string]float64 // per Delta call, nil for the priming call
	}{
		{name: "primes then deltas", reads: []float64{10, 13, 13}, want: []map[string]float64{{}, {"x": 3}, {"x": 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := 0
			s := &Sampler{Sources: []Source{{Name: "x", Read: func(context.Context) (float64, error) {
				v := tc.reads[i]
				i++
				return v, nil
			}}}}
			for n, want := range tc.want {
				got, err := s.Delta(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != len(want) || got["x"] != want["x"] {
					t.Errorf("call %d: %v, want %v", n, got, want)
				}
			}
		})
	}
}

func TestAuditLines(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    float64
		missing bool
	}{
		{name: "three events", content: "{}\n{}\n{}\n", want: 3},
		{name: "empty file", content: "", want: 0},
		{name: "missing file", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := AuditLines("audit", path).Read(context.Background())
			if tc.missing {
				if err == nil {
					t.Fatal("want an error for a missing log")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("got %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}
