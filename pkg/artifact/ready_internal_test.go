package artifact

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// TestAwaitReady drives the READY handshake with what a zygote may say
// or do on its control channel. A zygote that is silent speaks through
// a pipe nothing writes to, closed afterwards so the reader ends.
func TestAwaitReady(t *testing.T) {
	exited := errors.New("exit status 3")
	cases := []struct {
		name     string
		said     string // the zygote's line, "" for a channel that stays silent
		closed   bool   // the zygote closed the channel without a line
		exit     error  // the zygote exited first with this, nil for a clean exit
		exited   bool   // the zygote exited first
		canceled bool
		timeout  time.Duration // 0 waits a minute, longer than any case
		want     string        // the error, "" for READY
	}{
		{name: "READY", said: "READY\n"},
		{name: "READY with padding", said: "  READY \n"},
		{name: "another word", said: "HELLO\n", want: `artifact: zygote did not become ready: zygote said "HELLO", not READY`},
		{name: "the channel closed without a line", closed: true, want: "artifact: zygote did not become ready: EOF"},
		{name: "exited with an error first", exited: true, exit: exited, want: "artifact: zygote exited before READY: exit status 3"},
		{name: "exited cleanly first", exited: true, want: "artifact: zygote exited before READY"},
		{name: "never ready", timeout: time.Millisecond, want: "artifact: zygote did not become ready in time"},
		{name: "a canceled wait", canceled: true, want: context.Canceled.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ctl io.Reader = strings.NewReader(tc.said)
			if tc.said == "" && !tc.closed {
				r, w := io.Pipe()
				t.Cleanup(func() { _ = w.Close() })
				ctl = r
			}
			waited := make(chan error, 1)
			if tc.exited {
				waited <- tc.exit
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			if tc.timeout == 0 {
				tc.timeout = time.Minute
			}
			err := awaitReady(ctx, ctl, waited, tc.timeout)
			if tc.want == "" && err != nil {
				t.Fatalf("awaitReady = %v, want READY", err)
			}
			if tc.want != "" && (err == nil || err.Error() != tc.want) {
				t.Fatalf("awaitReady = %v, want %q", err, tc.want)
			}
			if tc.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("awaitReady = %v, want it to wrap %v", err, context.Canceled)
			}
			if tc.exited {
				select {
				case got := <-waited:
					if !errors.Is(got, tc.exit) {
						t.Fatalf("waited holds %v again, want %v", got, tc.exit)
					}
				default:
					t.Fatal("the exit was taken from waited and not put back")
				}
			}
		})
	}
}
