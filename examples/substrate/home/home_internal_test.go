package home

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"

	"github.com/helayoty/fiberd/examples/substrate/herder"
)

// TestWhatTheHomeOffers checks the home's fixed answers to the agent.
func TestWhatTheHomeOffers(t *testing.T) {
	scope := []core.ScopeClaim{{Name: "pod_uid", Value: "p-1"}, {Name: "node", Value: "n-1"}}
	h, _ := newHome(t, Config{Scope: scope})
	cases := []struct {
		name string
		got  func() string
		want string
	}{
		{"the home is named substrate", h.Name, "substrate"},
		{"the cgroup root is the configured subtree", h.CgroupRoot, h.cfg.CgroupRoot},
		{"callers reach fibers through the ingress, not an advertised endpoint", h.AdvertisedEndpoint, ""},
		{"scope is the configured claims", func() string { return fmt.Sprint(h.Scope()) }, fmt.Sprint(scope)},
		{"scope is a copy the caller may change", func() string {
			s := h.Scope()
			s[0].Value = "changed"
			return h.Scope()[0].Value
		}, "p-1"},
		{"a worker pod offers no fabric", func() string {
			fc, release, err := h.Fabric(context.Background(), core.Grant{UID: "g"})
			release()
			return fmt.Sprintf("%+v %v", fc, err)
		}, fmt.Sprintf("%+v %v", core.FabricChannel{}, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.got(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGrantFailures checks minting that cannot sign and a lane nobody
// drains. Neither may lose the grant the herder asked for.
func TestGrantFailures(t *testing.T) {
	ctx := context.Background()
	priv, err := grant.GenerateKey("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	cases := []struct {
		name   string
		cfg    Config
		mints  int // templates minted in a row, no one draining the lane
		err    bool
		queued int // events on the lane afterwards
	}{
		{name: "a public key cannot sign: no grant, nothing announced", cfg: Config{Key: &pub}, mints: 1, err: true},
		{name: "a full lane still hands out the grant; the agent admits it on its first Clone", mints: 65, queued: 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHome(t, tc.cfg)
			var last error
			for i := range tc.mints {
				tok, g, err := h.Grant(ctx, herder.Template{Atespace: "team-a", Name: fmt.Sprintf("t%d", i)}, 0)
				if err == nil && (tok == "" || g.UID == "") {
					t.Fatalf("mint %d: no grant without an error", i)
				}
				last = err
			}
			if (last != nil) != tc.err {
				t.Fatalf("last mint err = %v, want error %v", last, tc.err)
			}
			lane, _ := h.Grants(ctx)
			if len(lane) != tc.queued {
				t.Fatalf("lane holds %d events, want %d", len(lane), tc.queued)
			}
			if tc.err && len(h.grants) != 0 {
				t.Fatalf("a failed mint was kept: %v", h.grants)
			}
		})
	}
}

// TestProbeConfig checks that liveness is always alive without a probe,
// and otherwise follows atelet's socket answering a connect.
func TestProbeConfig(t *testing.T) {
	// A short directory, because unix socket paths are limited to about
	// 100 bytes.
	dir, err := os.MkdirTemp("/tmp", "sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "atelet.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	cases := []struct {
		name    string
		socket  string
		healthy bool
	}{
		{name: "no probe: alive", healthy: true},
		{name: "atelet answering on its socket: alive", socket: sock, healthy: true},
		{name: "no atelet on the socket: stale", socket: filepath.Join(dir, "missing.sock")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			h, _ := newHome(t, Config{ProbeSocket: tc.socket, StaleTTL: 10 * time.Second, Now: func() time.Time { return now }})
			now = now.Add(11 * time.Second) // the boot sync is stale now
			h.probe(context.Background())
			if got := h.Health().Healthy(now); got != tc.healthy {
				t.Fatalf("Healthy = %v, want %v", got, tc.healthy)
			}
		})
	}
}

// TestRun checks that Run probes at once and then every StaleTTL/2, and
// returns when its context ends.
func TestRun(t *testing.T) {
	cases := []struct {
		name   string
		probes int // probes to wait for before stopping
	}{
		{"the first probe and the ticker's", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probed := make(chan struct{}, 16)
			h, _ := newHome(t, Config{StaleTTL: 20 * time.Millisecond, Probe: func(context.Context) error {
				select {
				case probed <- struct{}{}:
				default:
				}
				return nil
			}})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { h.Run(ctx); close(done) }()
			for i := range tc.probes {
				select {
				case <-probed:
				case <-time.After(10 * time.Second):
					t.Fatalf("probe %d never came", i+1)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run kept going after its context ended")
			}
		})
	}
}

var _ fhome.Home = (*Home)(nil)

// TestDelegateOwn checks when the home remounts the Pod's cgroup mount:
// only after a read-only failure, and the delegation is then retried.
func TestDelegateOwn(t *testing.T) {
	errOther := errors.New("cgroup: enable memory: permission denied")
	errRemount := errors.New("mount: operation not permitted")
	cases := []struct {
		name       string
		delegate   []error // one result per attempt
		remount    error
		wantErr    error
		wantROFS   bool // the read-only cause stays in the error
		wantRemnts int
		wantCalls  int
	}{
		{name: "a writable mount delegates at once", delegate: []error{nil}, wantCalls: 1},
		{name: "a read-only mount is remounted and the delegation retried",
			delegate:   []error{fmt.Errorf("cgroup: agent leaf: %w", &os.PathError{Op: "mkdir", Path: "/sys/fs/cgroup/agent", Err: syscall.EROFS})},
			wantRemnts: 1, wantCalls: 2},
		{name: "a read-only mount that cannot be remounted fails with both reasons",
			delegate: []error{fmt.Errorf("cgroup: %w", syscall.EROFS)}, remount: errRemount,
			wantErr: errRemount, wantROFS: true, wantRemnts: 1, wantCalls: 1},
		{name: "a remount that does not help reports the second failure",
			delegate: []error{fmt.Errorf("cgroup: %w", syscall.EROFS), errOther},
			wantErr:  errOther, wantRemnts: 1, wantCalls: 2},
		{name: "any other failure is not a reason to remount", delegate: []error{errOther},
			wantErr: errOther, wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, remounts := 0, 0
			delegate := func(d cgroup.Dir) (cgroup.Dir, error) {
				var err error
				if calls < len(tc.delegate) {
					err = tc.delegate[calls] // attempts past the list succeed
				}
				calls++
				if err != nil {
					return cgroup.Dir{}, err
				}
				return d.Child("fiberd"), nil
			}
			remount := func(string) error { remounts++; return tc.remount }
			got, err := delegateOwn(t.TempDir(), delegate, remount)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && filepath.Base(got.Path) != "fiberd" {
				t.Fatalf("delegated %q, want the fiberd subtree", got.Path)
			}
			if errors.Is(err, syscall.EROFS) != tc.wantROFS {
				t.Fatalf("err = %v: read-only cause present = %v, want %v", err, !tc.wantROFS, tc.wantROFS)
			}
			if calls != tc.wantCalls || remounts != tc.wantRemnts {
				t.Fatalf("%d delegations and %d remounts, want %d and %d", calls, remounts, tc.wantCalls, tc.wantRemnts)
			}
		})
	}
}
