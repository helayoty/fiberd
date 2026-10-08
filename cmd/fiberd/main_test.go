package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is stderr shared between run and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// adminHealthy reports whether the admin socket answers GET /healthz.
func adminHealthy(sock string) bool {
	cl := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := cl.Get("http://admin/healthz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestRun: fiberd's exit codes and what it says on stderr, and a full
// start and clean stop of the standalone agent.
func TestRun(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// serve marks a case that starts the agent. It is stopped once
		// its admin socket answers.
		serve      bool
		wantCode   int
		wantStderr string
	}{
		{name: "-h prints the flags", args: []string{"-h"}, wantCode: 0, wantStderr: "-verifier"},
		{name: "an unknown flag", args: []string{"-nope"}, wantCode: 2, wantStderr: "flag provided but not defined: -nope"},
		{name: "a bad flag value", args: []string{"-stale-ttl", "later"}, wantCode: 2, wantStderr: "invalid value"},
		{name: "no verifier", args: []string{"-insecure-plaintext"}, wantCode: 1, wantStderr: "-verifier is required"},
		{name: "no transport", args: []string{"-verifier", "insecure-json"}, wantCode: 1, wantStderr: "TLS is required"},
		{name: "serves until stopped", args: []string{"-insecure-plaintext", "-verifier", "insecure-json"}, serve: true, wantCode: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Short, since the admin socket lives under it.
			state, err := os.MkdirTemp("", "fz")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(state) })
			sock := filepath.Join(state, "private", "admin.sock")
			args := append([]string{"-state", state, "-listen", "127.0.0.1:0", "-runtime", "stub"}, tc.args...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stderr syncBuffer
			done := make(chan int, 1)
			go func() { done <- run(ctx, args, &stderr) }()
			if tc.serve {
				deadline := time.Now().Add(20 * time.Second)
				for !adminHealthy(sock) {
					select {
					case code := <-done:
						t.Fatalf("run exited %d before serving: %s", code, stderr.String())
					default:
					}
					if time.Now().After(deadline) {
						t.Fatalf("the admin socket never answered: %s", stderr.String())
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}
			select {
			case code := <-done:
				if code != tc.wantCode {
					t.Fatalf("run = %d, want %d: %s", code, tc.wantCode, stderr.String())
				}
			case <-time.After(20 * time.Second):
				t.Fatal("run did not return")
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr %q, want %q", stderr.String(), tc.wantStderr)
			}
			if tc.serve {
				if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("admin socket left behind: %v", err)
				}
			}
		})
	}
}
