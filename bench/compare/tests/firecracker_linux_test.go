//go:build linux && integration

// Package comparetest holds the integration tests of the comparison
// benchmark's adapters: real processes, run with -tags integration.
package comparetest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/bench/compare/adapters/firecracker"
)

// TestMain doubles as the UFFD handler the exec launcher starts: it
// listens on the socket it is given and waits to be killed, or exits 2
// before listening.
func TestMain(m *testing.M) {
	switch os.Getenv("COMPARE_FC_FAKE_UFFD") {
	case "listen":
		if _, err := net.Listen("unix", os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "fake uffd handler:", err)
			os.Exit(2)
		}
		select {}
	case "exit":
		fmt.Fprintln(os.Stderr, "no memory file")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// TestFirecrackerUFFDHandler runs this binary as the page-fault handler
// through the exec launcher: its pid and RSS are the child's, it ends on
// Kill, and an early exit reports what it wrote to stderr.
func TestFirecrackerUFFDHandler(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string // of the exit, empty means it listens until killed
	}{
		{name: "listens until killed", mode: "listen"},
		{name: "an exit before listening carries stderr", mode: "exit", want: "exit status 2: no memory file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("COMPARE_FC_FAKE_UFFD", tc.mode)
			// Socket paths must stay short, so the dir is under /tmp.
			dir, err := os.MkdirTemp("/tmp", "fc-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			sock := filepath.Join(dir, "uffd.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			h, err := firecracker.Exec(firecracker.Options{UFFDHandler: os.Args[0]}).Handler(ctx, sock, filepath.Join(dir, "mem"))
			if err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- h.Wait() }()
			if tc.want != "" {
				if err := <-exited; err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("exit = %v, want %q", err, tc.want)
				}
				return
			}
			for {
				c, err := net.Dial("unix", sock)
				if err == nil {
					_ = c.Close()
					break
				}
				select {
				case err := <-exited:
					t.Fatalf("the handler exited before listening: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(2 * time.Millisecond):
				}
			}
			if h.Pid() <= 0 || h.Pid() == os.Getpid() {
				t.Errorf("pid %d is not a child's", h.Pid())
			}
			if n, err := h.RSS(); err != nil || n <= 0 {
				t.Errorf("rss %d, %v", n, err)
			}
			if err := h.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-exited; err == nil || !strings.Contains(err.Error(), "killed") {
				t.Errorf("exit after Kill = %v, want killed", err)
			}
		})
	}
}
