package core_test

import (
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestSourceHealthHysteresis checks that health degrades once the last
// sync is stale and recovers only when a sync brings the age under recover
// (stale/2). A mark in the (recover, stale) band does not flip it back.
// The steps run in order against one SourceHealth.
func TestSourceHealthHysteresis(t *testing.T) {
	t0 := time.Unix(0, 0)
	h := core.NewSourceHealth(10*time.Second, t0) // recover = 5s
	steps := []struct {
		name string
		mark time.Duration // MarkSync at t0+mark before probing, 0 means none
		at   time.Duration // probe Healthy at t0+at
		want bool
	}{
		{name: "fresh is healthy", at: 9 * time.Second, want: true},
		{name: "age at stale degrades", at: 10 * time.Second, want: false},
		{name: "a mark in the band does not recover (age 7s: >= recover, < stale)", mark: 10 * time.Second, at: 17 * time.Second, want: false},
		{name: "a mark bringing age under recover recovers", mark: 17 * time.Second, at: 18 * time.Second, want: true},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			if tc.mark != 0 {
				h.MarkSync(t0.Add(tc.mark))
			}
			if got := h.Healthy(t0.Add(tc.at)); got != tc.want {
				t.Fatalf("Healthy(t0+%v) = %v, want %v", tc.at, got, tc.want)
			}
		}) {
			return // later steps build on this one
		}
	}
}
