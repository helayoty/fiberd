package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"

	"github.com/helayoty/fiberd/examples/knative/activator"
)

func TestRevisionFlags(t *testing.T) {
	dir := t.TempDir()
	jwt := filepath.Join(dir, "api.jwt")
	if err := os.WriteFile(jwt, []byte("  token-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		values  []string // one Set call each
		want    []activator.Revision
		wantErr func(error) bool // for the last value
	}{
		{name: "a name and an inline grant",
			values: []string{"hello=eyJ.tok"},
			want:   []activator.Revision{{Name: "hello", Grant: "eyJ.tok"}}},
		{name: "a grant read from a file, trimmed, with options",
			values: []string{"api=@" + jwt + ",concurrency=4,mode=http"},
			want:   []activator.Revision{{Name: "api", Grant: "token-from-file", Concurrency: 4, Mode: "http"}}},
		{name: "the flag repeats",
			values: []string{"a=x", "b=y,mode=line"},
			want:   []activator.Revision{{Name: "a", Grant: "x"}, {Name: "b", Grant: "y", Mode: "line"}}},
		{name: "no = is refused",
			values:  []string{"hello"},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "want name=<jwt|@file>") }},
		{name: "no name is refused",
			values:  []string{"=tok"},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "want name=<jwt|@file>") }},
		{name: "a grant file that is missing",
			values: []string{"a=@" + filepath.Join(dir, "nope.jwt")},
			wantErr: func(err error) bool {
				return errors.Is(err, fs.ErrNotExist) && strings.HasPrefix(err.Error(), "-revision a: ")
			}},
		{name: "a concurrency that is not a number",
			values:  []string{"a=t,concurrency=many"},
			wantErr: func(err error) bool { return errors.Is(err, strconv.ErrSyntax) }},
		{name: "an unknown option",
			values:  []string{"a=t,colour=red"},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), `unknown option "colour"`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r revisionFlags
			var err error
			for _, v := range tc.values {
				if err = r.Set(v); err != nil {
					break
				}
			}
			if tc.wantErr != nil {
				if err == nil || !tc.wantErr(err) {
					t.Fatalf("Set = %v, not the error wanted", err)
				}
				if len(r) != len(tc.values)-1 {
					t.Fatalf("a refused value was kept: %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual([]activator.Revision(r), tc.want) {
				t.Fatalf("revisions = %+v, want %+v", r, tc.want)
			}
			if got := r.String(); got != strconv.Itoa(len(tc.want)) {
				t.Fatalf("String = %q, want the count %d", got, len(tc.want))
			}
		})
	}
}

// home is a fiberd home over real TCP that answers every Clone with a
// CREATE of a fiber at endpoint and records what it was asked.
type home struct {
	grantv1.UnimplementedFibersServer
	endpoint string
	mu       sync.Mutex
	clones   []*grantv1.CloneRequest
	parks    chan string
}

func (h *home) Clone(_ context.Context, req *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	h.mu.Lock()
	h.clones = append(h.clones, req)
	n := len(h.clones)
	h.mu.Unlock()
	return &grantv1.CloneResponse{
		FiberId: fmt.Sprintf("%s#%d", req.GetSession(), n), Endpoint: h.endpoint,
		Fence: &grantv1.Fence{GrantUid: "g", Epoch: 1, Seq: uint64(n)}, Kind: grantv1.CloneKind_CREATE,
	}, nil
}

func (h *home) Park(_ context.Context, req *grantv1.ParkRequest) (*emptypb.Empty, error) {
	select {
	case h.parks <- req.GetFiberId():
	default:
	}
	return &emptypb.Empty{}, nil
}

// startHome serves a home on a TCP port, with a line guest that answers
// "pong" behind the endpoint it hands out, and returns its address.
func startHome(t *testing.T) (*home, string) {
	t.Helper()
	listen := func() net.Listener {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lis.Close() })
		return lis
	}
	guest := listen()
	go func() {
		for {
			c, err := guest.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
					_, _ = io.WriteString(c, "pong\n")
				}
			}()
		}
	}()
	h := &home{endpoint: "tcp://" + guest.Addr().String(), parks: make(chan string, 64)}
	gs := grpc.NewServer()
	grantv1.RegisterFibersServer(gs, h)
	lis := listen()
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return h, lis.Addr().String()
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	jwt := filepath.Join(dir, "hello.jwt")
	if err := os.WriteFile(jwt, []byte("token-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	isUsage := func(err error) bool { var u usageError; return errors.As(err, &u) }

	cases := []struct {
		name string
		// args is the command line. $HOME is the test home's address and
		// $JWT the grant file.
		args    []string
		wantErr func(error) bool // nil when run serves until cancelled, then returns nil
		out     string           // a substring of the flag output
		// serve exercises a run that is serving on addr.
		serve func(t *testing.T, addr net.Addr, h *home)
	}{
		{name: "an unknown flag is a usage error",
			args: []string{"-nope"}, wantErr: isUsage, out: "flag provided but not defined: -nope"},
		{name: "-h prints the usage",
			args: []string{"-h"}, wantErr: func(err error) bool { return errors.Is(err, flag.ErrHelp) && isUsage(err) },
			out: "-revision value"},
		{name: "a bad -revision is a usage error",
			args: []string{"-revision", "hello"}, wantErr: isUsage, out: "want name=<jwt|@file>"},
		{name: "a home address that does not parse",
			args:    []string{"-home", "%zz", "-revision", "a=t"},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "invalid URL escape") }},
		{name: "no revision",
			args:    []string{"-home", "$HOME", "-listen", "127.0.0.1:0"},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "no revisions") }},
		{name: "a listen address already taken",
			args:    []string{"-home", "$HOME", "-listen", busy.Addr().String(), "-revision", "a=t"},
			wantErr: func(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }},
		{name: "serves a revision from a grant file and parks it when idle",
			args: []string{"-home", "$HOME", "-listen", "127.0.0.1:0", "-revision", "hello=@$JWT",
				"-idle", "20ms", "-clone-deadline", "3s"},
			serve: func(t *testing.T, addr net.Addr, h *home) {
				before := time.Now()
				resp, err := http.Get("http://" + addr.String() + "/hello")
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				after := time.Now()
				if resp.StatusCode != 200 || string(body) != "pong\n" ||
					resp.Header.Get("X-Fiberd-Session") != "hello-0" || resp.Header.Get("X-Fiberd-Clone") != "CREATE" {
					t.Fatalf("GET /hello = %d %q %v", resp.StatusCode, body, resp.Header)
				}
				h.mu.Lock()
				req := h.clones[0]
				h.mu.Unlock()
				if d := req.GetDeadline().AsTime(); req.GetGrantJwt() != "token-from-file" ||
					d.Before(before.Add(3*time.Second)) || d.After(after.Add(3*time.Second)) {
					t.Fatalf("Clone got grant %q deadline %v, want token-from-file within 3s of %v", req.GetGrantJwt(), d, before)
				}
				select {
				case id := <-h.parks:
					if id != "hello-0#1" {
						t.Fatalf("parked %q, want hello-0#1", id)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the idle fiber was never parked")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, addr := startHome(t)
			args := make([]string, len(tc.args))
			for i, a := range tc.args {
				args[i] = strings.NewReplacer("$HOME", addr, "$JWT", jwt).Replace(a)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out bytes.Buffer
			ready := make(chan net.Addr, 1)
			errc := make(chan error, 1)
			go func() { errc <- run(ctx, args, &out, func(a net.Addr) { ready <- a }) }()

			select {
			case err := <-errc:
				if tc.wantErr == nil || err == nil || !tc.wantErr(err) {
					t.Fatalf("run = %v, not the error wanted", err)
				}
				if !strings.Contains(out.String(), tc.out) {
					t.Fatalf("flag output %q lacks %q", out.String(), tc.out)
				}
				return
			case a := <-ready:
				if tc.wantErr != nil {
					cancel()
					t.Fatalf("run served on %s, want an error", a)
				}
				tc.serve(t, a, h)
			case <-time.After(10 * time.Second):
				t.Fatal("run neither failed nor served")
			}
			cancel()
			select {
			case err := <-errc:
				if err != nil {
					t.Fatalf("run after cancel = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("run did not stop when its context ended")
			}
		})
	}
}

// TestMainExit runs main in a child process and checks its exit status.
// It is 0 for -h, 2 for a bad command line and 1 for any other failure.
func TestMainExit(t *testing.T) {
	if args, ok := os.LookupEnv("FIBERD_ACTIVATOR_ARGS"); ok {
		os.Args = append([]string{"fiberd-activator"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	cases := []struct {
		name   string
		args   string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: "-h", code: 0, stderr: "Usage of fiberd-activator"},
		{name: "a bad flag exits 2", args: "-nope", code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "a failure exits 1", args: "-home %zz -revision a=t", code: 1, stderr: "invalid URL escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainExit$")
			cmd.Env = append(os.Environ(), "FIBERD_ACTIVATOR_ARGS="+tc.args)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("exit %d with %q, want %d with %q", code, stderr.String(), tc.code, tc.stderr)
			}
		})
	}
}
