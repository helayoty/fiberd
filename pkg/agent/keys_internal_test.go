package agent

import (
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
)

func saveKey(t *testing.T, gen func() (*jose.JSONWebKey, error)) (string, string) {
	t.Helper()
	k, err := gen()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := grant.SaveKey(path, k); err != nil {
		t.Fatal(err)
	}
	return path, k.KeyID
}

func edKey() (*jose.JSONWebKey, error) { return grant.GenerateKey(jose.EdDSA) }

// stateFor is a -state under a fresh directory, or a path under a file
// when unusable, so the private directory cannot be made.
func stateFor(t *testing.T, unusable bool) string {
	t.Helper()
	dir := t.TempDir()
	if !unusable {
		return filepath.Join(dir, "state")
	}
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(f, "state")
}

// TestLoadAuditKey checks that the audit checkpoints are signed with
// -audit-key, or with a key the home generates once under <state>/private and
// reuses.
func TestLoadAuditKey(t *testing.T) {
	given, givenKID := saveKey(t, edKey)
	seal, _ := saveKey(t, artifact.GenerateSealKey)
	cases := []struct {
		name     string
		flag     string
		unusable bool
		wantKID  string // "" for a generated key
		wantErr  bool
	}{
		{name: "generated on first use"},
		{name: "the flag's key", flag: given, wantKID: givenKID},
		{name: "a missing key", flag: "/nonexistent/k.json", wantErr: true},
		{name: "a key of the wrong kind", flag: seal, wantErr: true},
		{name: "no state to keep a key in", unusable: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{StateDir: stateFor(t, tc.unusable), AuditKey: tc.flag}
			cp, err := c.loadAuditKey()
			if tc.wantErr {
				if err == nil || !strings.HasPrefix(err.Error(), "-audit-key: ") {
					t.Fatalf("loadAuditKey: %v, want an -audit-key error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cp.Key) != ed25519.PrivateKeySize || cp.KeyID == "" {
				t.Fatalf("checkpoints key %d bytes kid %q", len(cp.Key), cp.KeyID)
			}
			gen := filepath.Join(c.PrivateDir(), "audit-key.json")
			if tc.wantKID != "" {
				if cp.KeyID != tc.wantKID {
					t.Fatalf("kid %s, want %s", cp.KeyID, tc.wantKID)
				}
				if _, err := os.Stat(gen); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("a key was generated although -audit-key names one")
				}
				return
			}
			if fi, err := os.Stat(gen); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("generated key: %v, want mode 0600", err)
			}
			again, err := c.loadAuditKey()
			if err != nil || again.KeyID != cp.KeyID {
				t.Fatalf("second load: kid %v, %v, want the same key", again, err)
			}
		})
	}
}

// TestLoadHandoffKey checks that handoff identities derive from -handoff-key,
// or from a 32-byte key the home generates once and reuses.
func TestLoadHandoffKey(t *testing.T) {
	given, _ := saveKey(t, artifact.GenerateSealKey)
	signing, _ := saveKey(t, edKey)
	cases := []struct {
		name     string
		flag     string
		unusable bool
		wantErr  bool
	}{
		{name: "generated on first use"},
		{name: "the flag's key", flag: given},
		{name: "a missing key", flag: "/nonexistent/k.json", wantErr: true},
		{name: "a signing key is not a handoff key", flag: signing, wantErr: true},
		{name: "no state to keep a key in", unusable: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{StateDir: stateFor(t, tc.unusable), HandoffKey: tc.flag}
			k, err := c.loadHandoffKey()
			if tc.wantErr {
				if err == nil || !strings.HasPrefix(err.Error(), "-handoff-key: ") {
					t.Fatalf("loadHandoffKey: %v, want a -handoff-key error", err)
				}
				return
			}
			if err != nil || len(k) != 32 {
				t.Fatalf("loadHandoffKey: %d bytes, %v, want 32", len(k), err)
			}
			if tc.flag != "" {
				want, err := artifact.LoadSealKey(tc.flag)
				if err != nil || string(want.Key) != string(k) {
					t.Fatal("the key is not the flag's")
				}
				return
			}
			again, err := c.loadHandoffKey()
			if err != nil || string(again) != string(k) {
				t.Fatal("a second load changed the key")
			}
		})
	}
}

// TestStateKey checks that the flag's path wins. Otherwise an existing file is
// reused, a missing one generated, and a failure to make or save one is
// returned.
func TestStateKey(t *testing.T) {
	cases := []struct {
		name     string
		flag     string
		existing string // body of the file already there
		dangling bool   // the name is a symlink to a missing directory
		genErr   error
		wantGen  bool
		wantErr  string
	}{
		{name: "the flag's path, unread", flag: "/given/key.json"},
		{name: "an existing file is reused as is", existing: "kept"},
		{name: "a missing file is generated", wantGen: true},
		{name: "the generator fails", genErr: errors.New("no entropy"), wantErr: "no entropy"},
		{name: "the key cannot be saved", dangling: true, wantErr: "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{StateDir: filepath.Join(t.TempDir(), "state")}
			path := filepath.Join(c.PrivateDir(), "k.json")
			if tc.existing != "" || tc.dangling {
				if err := os.MkdirAll(c.PrivateDir(), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.existing != "" {
				if err := os.WriteFile(path, []byte(tc.existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.dangling {
				if err := os.Symlink(filepath.Join(t.TempDir(), "gone", "k.json"), path); err != nil {
					t.Fatal(err)
				}
			}
			gens := 0
			gen := func() (*jose.JSONWebKey, error) {
				gens++
				if tc.genErr != nil {
					return nil, tc.genErr
				}
				return edKey()
			}
			got, err := c.stateKey(tc.flag, "k.json", gen, "test key", "share it")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("stateKey: %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := path
			if tc.flag != "" {
				want = tc.flag
			}
			if got != want {
				t.Fatalf("stateKey = %s, want %s", got, want)
			}
			if (gens == 1) != tc.wantGen {
				t.Fatalf("generated %d keys, want generated=%v", gens, tc.wantGen)
			}
			if tc.existing != "" {
				if b, _ := os.ReadFile(path); string(b) != tc.existing {
					t.Fatalf("existing key rewritten: %q", b)
				}
			}
			if tc.wantGen {
				if _, err := grant.LoadKey(path); err != nil {
					t.Fatalf("generated key unreadable: %v", err)
				}
			}
		})
	}
}

// badAddr is an address whose string has no port.
type badAddr struct{}

func (badAddr) Network() string { return "tcp" }
func (badAddr) String() string  { return "no-port" }

// TestHandoffAdvertise checks that -handoff-advertise wins. Otherwise the bound
// address is advertised, its wildcard host replaced by -endpoint-host or
// the loopback.
func TestHandoffAdvertise(t *testing.T) {
	tcp := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	cases := []struct {
		name                string
		advertise, endpoint string
		addr                net.Addr
		want, wantErr       string
	}{
		{name: "the flag wins", advertise: "edge.example:443", addr: tcp("0.0.0.0:7"), want: "tcp://edge.example:443"},
		{name: "a flag without a port", advertise: "edge.example", addr: tcp("0.0.0.0:7"), wantErr: "-handoff-advertise"},
		{name: "a bound host is kept", addr: tcp("192.0.2.4:7"), endpoint: "10.0.0.1", want: "tcp://192.0.2.4:7"},
		{name: "a wildcard takes the endpoint host", addr: tcp("0.0.0.0:7"), endpoint: "10.0.0.1", want: "tcp://10.0.0.1:7"},
		{name: "an IPv6 wildcard takes an IPv6 endpoint host", addr: tcp("[::]:7"), endpoint: "fd00::1", want: "tcp://[fd00::1]:7"},
		{name: "a wildcard without an endpoint host is the loopback", addr: tcp("[::]:7"), want: "tcp://127.0.0.1:7"},
		{name: "an address without a port", addr: badAddr{}, wantErr: "missing port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{HandoffAdvertise: tc.advertise, EndpointHost: tc.endpoint}
			got, err := c.handoffAdvertise(tc.addr)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("handoffAdvertise = %q, %v, want %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("handoffAdvertise = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// TestEndpointPolicy checks that unix needs nothing more. inet4 and inet6
// take the declared host, or the family's loopback, and the fixed port range.
func TestEndpointPolicy(t *testing.T) {
	cases := []struct {
		name, family, host string
		want               endpoint.Policy
		wantErr            string
	}{
		{name: "unix", family: "unix", want: endpoint.Policy{Family: endpoint.Unix}},
		{name: "unix ignores a host", family: "unix", host: "10.0.0.1", want: endpoint.Policy{Family: endpoint.Unix, Host: "10.0.0.1"}},
		{name: "inet4 defaults to its loopback", family: "inet4",
			want: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 30000, PortMax: 32767}},
		{name: "inet6 defaults to its loopback", family: "inet6",
			want: endpoint.Policy{Family: endpoint.Inet6, Host: "::1", PortMin: 30000, PortMax: 32767}},
		{name: "a declared host", family: "inet4", host: "10.0.0.1",
			want: endpoint.Policy{Family: endpoint.Inet4, Host: "10.0.0.1", PortMin: 30000, PortMax: 32767}},
		{name: "a host of the other family", family: "inet6", host: "10.0.0.1", wantErr: "is not an inet6 address"},
		{name: "a host that is not an IP", family: "inet4", host: "node.example", wantErr: "not an IP literal"},
		{name: "an unknown family", family: "appletalk", wantErr: "want unix, inet4 or inet6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{EndpointFamily: tc.family, EndpointHost: tc.host}
			got, err := c.endpointPolicy()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("endpointPolicy: %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("endpointPolicy = %+v, %v, want %+v", got, err, tc.want)
			}
		})
	}
}
