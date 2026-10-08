package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// syncBuffer is a bytes.Buffer safe to write from a serving goroutine
// while the test reads it.
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

// call runs the command with args and returns its exit code and output.
func call(ctx context.Context, args ...string) (int, string, string) {
	var stdout, stderr syncBuffer
	code := run(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// keyFile generates a key with keygen and returns its path.
func keyFile(t *testing.T, alg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.json")
	if code, _, stderr := call(context.Background(), "keygen", "-alg", alg, "-out", path); code != 0 {
		t.Fatalf("keygen: exit %d: %s", code, stderr)
	}
	return path
}

// The command dispatches subcommands and maps outcomes to exit codes: 0
// for success and help, 2 for usage errors, 1 for failures.
func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		want       int
		wantStderr string
	}{
		{name: "no subcommand is a usage error", want: 2, wantStderr: "usage: grant-issuer"},
		{name: "help prints usage", args: []string{"help"}, want: 0, wantStderr: "usage: grant-issuer"},
		{name: "-h prints usage", args: []string{"-h"}, want: 0, wantStderr: "usage: grant-issuer"},
		{name: "an unknown subcommand fails", args: []string{"sign"}, want: 1, wantStderr: `unknown subcommand "sign"`},
		{name: "-h on a subcommand prints its flags", args: []string{"mint", "-h"}, want: 0, wantStderr: "-aud"},
		{name: "an unknown flag is a usage error", args: []string{"keygen", "-bogus"}, want: 2, wantStderr: "flag provided but not defined: -bogus"},
		{name: "serve rejects a bad flag", args: []string{"serve", "-addr"}, want: 2, wantStderr: "flag needs an argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := call(context.Background(), tc.args...)
			if code != tc.want || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("exit %d, stderr %q, want %d with %q", code, stderr, tc.want, tc.wantStderr)
			}
		})
	}
}

// keygen writes an owner-only private JWK of the asked algorithm and
// names it on stdout.
func TestKeygen(t *testing.T) {
	cases := []struct {
		name       string
		alg        string
		out        func(dir string) string
		wantKty    string
		wantStderr string
	}{
		{name: "an EdDSA signing key", alg: "EdDSA", wantKty: "OKP"},
		{name: "an ES256 signing key", alg: "ES256", wantKty: "EC"},
		{name: "an A256GCM seal key", alg: "A256GCM", wantKty: "oct"},
		{name: "an unsupported algorithm fails", alg: "RS256", wantStderr: "unsupported algorithm"},
		{name: "an unwritable path fails", alg: "EdDSA", wantStderr: "no such file",
			out: func(dir string) string { return filepath.Join(dir, "missing", "key.json") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "key.json")
			if tc.out != nil {
				out = tc.out(dir)
			}
			code, stdout, stderr := call(context.Background(), "keygen", "-alg", tc.alg, "-out", out)
			if tc.wantStderr != "" {
				if code != 1 || !strings.Contains(stderr, tc.wantStderr) {
					t.Fatalf("exit %d, stderr %q, want 1 with %q", code, stderr, tc.wantStderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var k map[string]any
			if err := json.Unmarshal(b, &k); err != nil {
				t.Fatal(err)
			}
			if k["kty"] != tc.wantKty || k["alg"] != tc.alg || k["kid"] == "" {
				t.Fatalf("key = %s, want kty %s alg %s with a kid", b, tc.wantKty, tc.alg)
			}
			if want := "wrote " + out + " kid=" + k["kid"].(string) + " alg=" + tc.alg + "\n"; stdout != want {
				t.Fatalf("stdout = %q, want %q", stdout, want)
			}
			if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode = %v, %v, want 0600", fi.Mode().Perm(), err)
			}
		})
	}
}

// mint prints one token carrying every flag, verifiable with the key's
// public half. A flag it cannot read fails before anything is signed.
func TestMint(t *testing.T) {
	key := keyFile(t, "EdDSA")
	k, err := grant.LoadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public()
	seal := keyFile(t, "A256GCM")
	dir := t.TempDir()
	caller := tlsconftest.NewCA(t, "ca").Client(t, "caller")
	certFile, keyPEM := caller.Write(t, dir, "caller")
	base := []string{"mint", "-key", key, "-issuer", "https://issuer.test", "-aud", "node-a"}

	cases := []struct {
		name       string
		args       []string
		check      func(t *testing.T, g core.Grant)
		wantStderr string
	}{
		{name: "defaults: one fiber, untrusted, direct, best effort, a random uid, ten minutes",
			check: func(t *testing.T, g core.Grant) {
				if !regexp.MustCompile(`^g-[0-9a-f]{16}$`).MatchString(g.UID) {
					t.Fatalf("uid = %q, want g-<16 hex>", g.UID)
				}
				if g.FiberMax != 1 || g.Policy.Isolation != core.Untrusted || g.Policy.EndpointMode != core.EndpointDirect ||
					g.Policy.Durability != core.BestEffort || g.MinTier != core.TierBasic || g.CallerThumbprint != "" {
					t.Fatalf("grant = %+v, want the defaults", g)
				}
				if left := time.Until(g.LeaseExpiry); left < 9*time.Minute || left > 10*time.Minute {
					t.Fatalf("lease expires in %s, want about ten minutes", left)
				}
			}},
		{name: "every flag lands in the grant",
			args: []string{"-uid", "g-7", "-template", "sha256:abc", "-max", "8", "-warm", "2", "-w-budget", "64Mi",
				"-min-tier", "FIBER_CHECKPOINT", "-ttl", "1h", "-durability", "sync", "-psi-shed", "40", "-psi-park", "20",
				"-device-budget", "1Gi", "-device-class", "gpu", "-bind-cert", certFile, "-isolation", "TRUSTED", "-endpoint-mode", "HANDOFF"},
			check: func(t *testing.T, g core.Grant) {
				want := core.Grant{UID: "g-7", Issuer: "https://issuer.test", Audience: "node-a", TemplateDigest: "sha256:abc",
					FiberMax: 8, FiberWarm: 2, WBudgetBytes: 64 << 20, MinTier: core.TierCheckpoint, LeaseExpiry: g.LeaseExpiry,
					Policy: core.Policy{Durability: core.Sync, PSISomeAvg10Shed: 40, PSISomeAvg10Park: 20,
						Isolation: core.Trusted, EndpointMode: core.EndpointHandoff},
					DeviceBudget:     core.DeviceBudget{Bytes: 1 << 30, Class: "gpu"},
					CallerThumbprint: tlsconf.Thumbprint(caller.Cert)}
				if g != want {
					t.Fatalf("grant\n got %+v\nwant %+v", g, want)
				}
				if left := time.Until(g.LeaseExpiry); left < 59*time.Minute || left > time.Hour {
					t.Fatalf("lease expires in %s, want about an hour", left)
				}
			}},
		{name: "a negative ttl mints an expired grant", args: []string{"-ttl", "-1m", "-durability", "BEST_EFFORT"},
			check: func(t *testing.T, g core.Grant) {
				if !g.Expired(time.Now()) {
					t.Fatalf("lease %s, want it past", g.LeaseExpiry)
				}
			}},
		{name: "no issuer fails", args: []string{"-issuer", ""}, wantStderr: "-issuer and -aud are required"},
		{name: "no audience fails", args: []string{"-aud", ""}, wantStderr: "-issuer and -aud are required"},
		{name: "a missing key fails", args: []string{"-key", filepath.Join(dir, "nope.json")}, wantStderr: "no such file"},
		{name: "a seal key cannot sign", args: []string{"-key", seal}, wantStderr: "is not valid"},
		{name: "an unknown tier fails", args: []string{"-min-tier", "FIBER_GOLD"}, wantStderr: "FIBER_GOLD"},
		{name: "an unknown isolation fails", args: []string{"-isolation", "SOMEWHAT"}, wantStderr: "-isolation"},
		{name: "an unknown endpoint mode fails", args: []string{"-endpoint-mode", "TUNNEL"}, wantStderr: "-endpoint-mode"},
		{name: "a bad w budget fails", args: []string{"-w-budget", "lots"}, wantStderr: "-w-budget"},
		{name: "a bad device budget fails", args: []string{"-device-budget", "1Ti"}, wantStderr: "-device-budget"},
		{name: "an unknown durability fails", args: []string{"-durability", "eventually"}, wantStderr: `-durability: "eventually"`},
		{name: "a bind cert that is not a certificate fails", args: []string{"-bind-cert", keyPEM}, wantStderr: "-bind-cert"},
		{name: "a uid no home accepts fails", args: []string{"-uid", "G_1"}, wantStderr: "DNS-1123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := call(context.Background(), append(append([]string{}, base...), tc.args...)...)
			if tc.wantStderr != "" {
				if code != 1 || stdout != "" || !strings.Contains(stderr, tc.wantStderr) {
					t.Fatalf("exit %d, stdout %q, stderr %q, want 1 with %q", code, stdout, stderr, tc.wantStderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			g, err := grant.Verify(strings.TrimSuffix(stdout, "\n"), &pub, grant.VerifyOptions{Audience: "node-a", Issuer: "https://issuer.test"})
			if err != nil {
				t.Fatalf("verify the minted token: %v", err)
			}
			tc.check(t, g)
		})
	}
}

// serve publishes discovery and the key set until its context ends, and
// fails to start on a bad key or an address it cannot bind.
func TestServe(t *testing.T) {
	key := keyFile(t, "ES256")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	listening := regexp.MustCompile(`grant-issuer serving (\S+) \(kid=\S+ alg=ES256\) on (\S+)`)

	cases := []struct {
		name       string
		args       []string
		wantIssuer string // the issuer discovery names
		wantStderr string // on failure
	}{
		{name: "an explicit issuer URL is published", args: []string{"-addr", "127.0.0.1:0", "-issuer", "https://issuer.test/"},
			wantIssuer: "https://issuer.test"},
		{name: "the default issuer URL is built from the address", args: []string{"-addr", "127.0.0.1:0"},
			wantIssuer: "http://127.0.0.1:0"},
		{name: "a missing key fails", args: []string{"-key", "/nonexistent/key.json", "-addr", "127.0.0.1:0"}, wantStderr: "no such file"},
		{name: "a busy address fails", args: []string{"-addr", busy.Addr().String()}, wantStderr: "address already in use"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr syncBuffer
			done := make(chan int, 1)
			args := append([]string{"serve", "-key", key}, tc.args...)
			go func() { done <- run(ctx, args, &stdout, &stderr) }()
			if tc.wantStderr != "" {
				select {
				case code := <-done:
					if code != 1 || !strings.Contains(stderr.String(), tc.wantStderr) {
						t.Fatalf("exit %d, stderr %q, want 1 with %q", code, stderr.String(), tc.wantStderr)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("serve did not fail")
				}
				return
			}

			var addr string
			deadline := time.Now().Add(10 * time.Second)
			for addr == "" {
				if m := listening.FindStringSubmatch(stderr.String()); m != nil {
					addr = m[2]
				} else if time.Now().After(deadline) {
					t.Fatalf("serve never said where it listens: %q", stderr.String())
				} else {
					time.Sleep(time.Millisecond)
				}
			}
			resp, err := http.Get("http://" + addr + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatal(err)
			}
			var d map[string]any
			err = json.NewDecoder(resp.Body).Decode(&d)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if d["issuer"] != tc.wantIssuer || d["jwks_uri"] != tc.wantIssuer+"/openid/v1/jwks" {
				t.Fatalf("discovery = %v, want issuer %s", d, tc.wantIssuer)
			}
			resp, err = http.Get("http://" + addr + "/openid/v1/jwks")
			if err != nil {
				t.Fatal(err)
			}
			var set jose.JSONWebKeySet
			err = json.NewDecoder(resp.Body).Decode(&set)
			_ = resp.Body.Close()
			if err != nil || len(set.Keys) != 1 || !set.Keys[0].IsPublic() {
				t.Fatalf("jwks = %+v, %v, want one public key", set, err)
			}

			cancel()
			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("serve exited %d after cancel: %s", code, stderr.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("serve did not stop after cancel")
			}
		})
	}
}

func TestDefaultIssuer(t *testing.T) {
	cases := []struct{ addr, want string }{
		{addr: ":8686", want: "http://localhost:8686"},
		{addr: "10.0.0.7:8686", want: "http://10.0.0.7:8686"},
		{addr: "issuer.test:80", want: "http://issuer.test:80"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := defaultIssuer(tc.addr); got != tc.want {
				t.Fatalf("defaultIssuer(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// Byte sizes take decimal and binary suffixes.
func TestParseBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{in: "0", want: 0},
		{in: "4096", want: 4096},
		{in: " 64Mi ", want: 64 << 20},
		{in: "2Ki", want: 2 << 10},
		{in: "1Gi", want: 1 << 30},
		{in: "3K", want: 3000},
		{in: "5M", want: 5_000_000},
		{in: "2G", want: 2_000_000_000},
		{in: "7 Mi", want: 7 << 20},
		{in: "", wantErr: true},
		{in: "Mi", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "1.5Gi", wantErr: true},
		{in: "1Ti", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseBytes(tc.in)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("parseBytes(%q) = %d, %v, want %d (error %v)", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}
