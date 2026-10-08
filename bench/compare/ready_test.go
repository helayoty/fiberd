package compare

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// serve answers connections on ln with the given replies in order, the
// last one repeating. An empty reply closes the connection unanswered.
func serve(t *testing.T, ln net.Listener, replies []string) {
	t.Helper()
	go func() {
		i := 0
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r := replies[min(i, len(replies)-1)]
			i++
			_, _ = bufio.NewReader(c).ReadString('\n')
			if r != "" {
				_, _ = c.Write([]byte(r))
			}
			_ = c.Close()
		}
	}()
}

const ok200 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n7\n"

func TestProbe(t *testing.T) {
	cases := []struct {
		name    string
		framing Framing
		replies []string
		// late starts the listener after the probe began, so the first
		// dials are refused.
		late         bool
		wantAttempts int
		wantBody     string
		wantErr      bool
	}{
		{name: "http answers at once", framing: HTTP, replies: []string{ok200}, wantBody: "7"},
		{name: "http after a 503", framing: HTTP, replies: []string{"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n", ok200}, wantAttempts: 1, wantBody: "7"},
		{name: "http after an empty reply", framing: HTTP, replies: []string{"", ok200}, wantAttempts: 1, wantBody: "7"},
		{name: "http after refused connections", framing: HTTP, replies: []string{ok200}, late: true, wantBody: "7"},
		{name: "line answers", framing: Line, replies: []string{"3\n"}, wantBody: "3"},
		{name: "line error then counter", framing: Line, replies: []string{"err unknown command\n", "1\n"}, wantAttempts: 1, wantBody: "1"},
		{name: "never answers", framing: HTTP, replies: []string{""}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			addr := ln.Addr().String()
			if tc.late {
				_ = ln.Close()
				go func() {
					time.Sleep(30 * time.Millisecond)
					l2, err := net.Listen("tcp", addr)
					if err != nil {
						return
					}
					ln = l2
					serve(t, l2, tc.replies)
				}()
			} else {
				serve(t, ln, tc.replies)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			before := time.Now()
			r, err := Probe{Dial: TCP(addr), Framing: tc.framing, Poll: time.Millisecond}.Run(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
				if !strings.Contains(err.Error(), "not ready after") {
					t.Fatalf("error %v should count attempts", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Body != tc.wantBody {
				t.Errorf("body %q, want %q", r.Body, tc.wantBody)
			}
			if tc.late && r.Attempts == 0 {
				t.Error("refused dials should count as attempts")
			}
			if !tc.late && r.Attempts != tc.wantAttempts {
				t.Errorf("attempts %d, want %d", r.Attempts, tc.wantAttempts)
			}
			if r.FirstByte.Before(before) || r.FirstByte.After(time.Now()) {
				t.Errorf("first byte %v outside the probe", r.FirstByte)
			}
		})
	}
}
