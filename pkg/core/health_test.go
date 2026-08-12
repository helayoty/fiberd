package core

import (
	"testing"
	"time"
)

func TestSourceHealthHysteresis(t *testing.T) {
	t0 := time.Unix(0, 0)
	h := NewSourceHealth(10*time.Second, t0) // recover = 5s

	if !h.Healthy(t0.Add(9 * time.Second)) {
		t.Fatal("fresh must be healthy")
	}
	if h.Healthy(t0.Add(10 * time.Second)) {
		t.Fatal("age >= stale must degrade")
	}
	// a mark landing in the (recover, stale) band must NOT flip back:
	h.MarkSync(t0.Add(10 * time.Second))
	if h.Healthy(t0.Add(17 * time.Second)) { // age 7s: >= recover, < stale
		t.Fatal("band-mark must not recover")
	}
	// a mark bringing age under recover does:
	h.MarkSync(t0.Add(17 * time.Second))
	if !h.Healthy(t0.Add(18 * time.Second)) {
		t.Fatal("age < recover must recover")
	}
}
