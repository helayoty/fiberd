package helper

import (
	"strings"
	"testing"
)

const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// TestRedact pins what the command log shows: a seed and a payload by
// their size, everything else whole, as the Rust helper logs.
func TestRedact(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"CLONE with a payload", "CLONE f /ep 500 6869 1 " + seed, "CLONE f /ep 500 payload:2B 1 seed:32B"},
		{"CLONE without a payload", "CLONE f /ep 500 - 3 " + seed, "CLONE f /ep 500 - 3 seed:32B"},
		{"RESUME", "RESUME f /park /ep 2000 2 " + seed, "RESUME f /park /ep 2000 2 seed:32B"},
		{"CLONE from before the seed", "CLONE f /ep 500 -", "CLONE f /ep 500 -"},
		{"PARK", "PARK f /park 1", "PARK f /park 1"},
		{"KILL", "KILL f", "KILL f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redact(strings.Fields(tc.line))
			if got != tc.want {
				t.Fatalf("redact = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, seed) {
				t.Fatalf("the log line holds the seed: %q", got)
			}
		})
	}
}

// TestParseIncarnation pins that a CLONE or RESUME carries a generation
// of 1 or more and 32 seed bytes, and that anything else is refused by
// name before a sandbox is made.
func TestParseIncarnation(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantGen int
		wantErr string
	}{
		{name: "a clone", line: "CLONE f /ep 500 - 1 " + seed, wantGen: 1},
		{name: "a resume", line: "RESUME f /park /ep 2000 7 " + seed, wantGen: 7},
		{name: "a line from before the seed", line: "CLONE f /ep 500 -", wantErr: "needs 6 fields"},
		{name: "generation 0", line: "CLONE f /ep 500 - 0 " + seed, wantErr: "not an incarnation"},
		{name: "a generation with a leading zero", line: "CLONE f /ep 500 - 01 " + seed, wantErr: "not an incarnation"},
		{name: "a generation that is not a number", line: "CLONE f /ep 500 - x " + seed, wantErr: "not an incarnation"},
		{name: "a short seed", line: "CLONE f /ep 500 - 1 0011", wantErr: "32 hex bytes"},
		{name: "a seed that is not hex", line: "CLONE f /ep 500 - 1 " + seed[:62] + "zz", wantErr: "32 hex bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := parseIncarnation(strings.Fields(tc.line))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b.generation != tc.wantGen || b.seed[1] != 1 || b.seed[31] != 0x1f {
				t.Fatalf("birth = %+v, want generation %d with the seed", b, tc.wantGen)
			}
		})
	}
}
