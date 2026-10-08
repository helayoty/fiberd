package agent_test

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/artifact"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
)

// parse binds a fresh Config, parses args and finishes it.
func parse(args ...string) (*agent.Config, error) {
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c agent.Config
	c.Bind(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	c.Finish()
	return &c, nil
}

// TestBind: the flags' defaults, what parsing makes of repeatable and
// list flags, and the values Bind refuses.
func TestBind(t *testing.T) {
	hostname, _ := os.Hostname()
	cases := []struct {
		name    string
		args    []string
		want    map[string]any // Config field -> value
		wantErr string
	}{
		{name: "defaults", want: map[string]any{
			"Listen": ":8484", "Advertise": ":8484", "HTTPAddr": "", "StateDir": "/var/lib/fiberd", "NodeID": hostname,
			"Verifier": "", "Issuer": "", "JWKSMaxStale": time.Hour, "MaxLease": time.Duration(0),
			"CgroupRoot": "/sys/fs/cgroup/fiberd", "RuntimeName": "stub", "RuntimeTier": "FIBER_CHECKPOINT",
			"Templates": map[string]string{}, "RunDir": "/run/fiberd", "EndpointFamily": "unix", "EndpointHost": "",
			"CRIUBin": "criu", "GrantCeiling": uint64(0), "AllCaps": false, "UsernsPool": runcbackend.DefaultPool,
			"FiberHide": []string(nil), "Runsc": "runsc", "Runc": "runc", "Parity": "strict", "InsecurePlaintext": false,
			"Devices": []string(nil), "StaleTTL": 30 * time.Second, "StatusEvery": time.Second, "PressureEvery": time.Second,
		}},
		{name: "advertise defaults to the listen address", args: []string{"-listen", "10.0.0.1:9"},
			want: map[string]any{"Listen": "10.0.0.1:9", "Advertise": "10.0.0.1:9"}},
		{name: "an explicit advertise address is kept", args: []string{"-advertise", "home:1"},
			want: map[string]any{"Listen": ":8484", "Advertise": "home:1"}},
		{name: "templates repeat and later ones win", args: []string{"-template", "sha256:a=/bin/a --x", "-template", " default = /bin/d ", "-template", "sha256:a=/bin/b"},
			want: map[string]any{"Templates": map[string]string{"sha256:a": "/bin/b", "default": "/bin/d"}}},
		{name: "a template without a command is refused", args: []string{"-template", "sha256:a="}, wantErr: "want digest=path"},
		{name: "fiber-hide repeats", args: []string{"-fiber-hide", "/a", "-fiber-hide", "/b"},
			want: map[string]any{"FiberHide": []string{"/a", "/b"}}},
		{name: "devices are trimmed and empty entries dropped", args: []string{"-devices", " gpu0, ,gpu1 ,"},
			want: map[string]any{"Devices": []string{"gpu0", "gpu1"}}},
		{name: "durations and numbers parse", args: []string{"-stale-ttl", "5s", "-max-lease", "1m", "-grant-ceiling", "4096", "-all-caps"},
			want: map[string]any{"StaleTTL": 5 * time.Second, "MaxLease": time.Minute, "GrantCeiling": uint64(4096), "AllCaps": true}},
		{name: "a bad duration is refused", args: []string{"-status-interval", "soon"}, wantErr: "invalid value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse(tc.args...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parse: %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			v := reflect.ValueOf(c).Elem()
			for field, want := range tc.want {
				f := v.FieldByName(field)
				if !f.IsValid() {
					t.Fatalf("Config has no field %s", field)
				}
				if got := f.Interface(); !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v", field, got, want)
				}
			}
		})
	}
}

// TestFinishIsIdempotent: finishing twice does not repeat the device
// list.
func TestFinishIsIdempotent(t *testing.T) {
	cases := []struct {
		name string
		runs int
	}{{name: "once", runs: 1}, {name: "three times", runs: 3}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse("-devices", "a,b")
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i < tc.runs; i++ {
				c.Finish()
			}
			if !reflect.DeepEqual(c.Devices, []string{"a", "b"}) {
				t.Fatalf("Devices = %v", c.Devices)
			}
		})
	}
}

func TestListenPort(t *testing.T) {
	cases := []struct {
		listen, want, wantErr string
	}{
		{listen: ":8484", want: "8484"},
		{listen: "127.0.0.1:0", want: "0"},
		{listen: "[::1]:9", want: "9"},
		{listen: "no-port", wantErr: `-listen "no-port"`},
	}
	for _, tc := range cases {
		t.Run(tc.listen, func(t *testing.T) {
			c := agent.Config{Listen: tc.listen}
			got, err := c.ListenPort()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ListenPort = %q, %v, want %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ListenPort = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestFamily(t *testing.T) {
	cases := []struct {
		family  string
		want    endpoint.Family
		wantErr bool
	}{
		{family: "", want: endpoint.Unix},
		{family: "unix", want: endpoint.Unix},
		{family: "inet4", want: endpoint.Inet4},
		{family: "INET6", want: endpoint.Inet6},
		{family: "ipx", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			c := agent.Config{EndpointFamily: tc.family}
			got, err := c.Family()
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("Family = %q, %v, want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestPaths: the private directory and the admin socket sit under
// -state.
func TestPaths(t *testing.T) {
	cases := []struct {
		state, private, admin string
	}{
		{state: "/var/lib/fiberd", private: "/var/lib/fiberd/private", admin: "/var/lib/fiberd/private/admin.sock"},
		{state: "rel/", private: "rel/private", admin: "rel/private/admin.sock"},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			c := agent.Config{StateDir: tc.state}
			if c.PrivateDir() != tc.private || c.AdminSocket() != tc.admin {
				t.Fatalf("PrivateDir %s AdminSocket %s, want %s %s", c.PrivateDir(), c.AdminSocket(), tc.private, tc.admin)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeKey saves a fresh key of alg (or a seal key when alg is empty)
// and returns its path and kid.
func writeKey(t *testing.T, alg jose.SignatureAlgorithm) (string, string) {
	t.Helper()
	var k *jose.JSONWebKey
	var err error
	if alg == "" {
		k, err = artifact.GenerateSealKey()
	} else {
		k, err = grant.GenerateKey(alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := grant.SaveKey(path, k); err != nil {
		t.Fatal(err)
	}
	return path, k.KeyID
}

// TestLoadDeltaKeys: no registry needs no keys. With one, the home signs
// and seals with the keys the flags name, or with keys of its own that it
// generates once under <state>/private, mode 0600, and reuses.
func TestLoadDeltaKeys(t *testing.T) {
	signer, signerKID := writeKey(t, jose.EdDSA)
	seal, sealKID := writeKey(t, "")
	trust := filepath.Join(t.TempDir(), "trust.json")
	other, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trust, mustJSON(t, grant.PublicJWKS(other)), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := "/nonexistent/key.json"
	cases := []struct {
		name                    string
		registry                string
		deltaKey, trust, sealed string
		stateIsFile             bool
		wantSigner, wantSeal    string // kid, "gen" for a generated key
		wantTrust               int
		wantErr                 string
	}{
		{name: "no registry, no keys"},
		{name: "generated on first use", registry: "r/d", wantSigner: "gen", wantSeal: "gen"},
		{name: "the flags' keys", registry: "r/d", deltaKey: signer, sealed: seal, trust: trust,
			wantSigner: signerKID, wantSeal: sealKID, wantTrust: 1},
		{name: "a missing signing key", registry: "r/d", deltaKey: missing, wantErr: "-delta-key/-delta-trust"},
		{name: "a missing trust file", registry: "r/d", deltaKey: signer, trust: missing, wantErr: "-delta-key/-delta-trust"},
		{name: "a missing seal key", registry: "r/d", deltaKey: signer, sealed: missing, wantErr: "-delta-seal-key"},
		{name: "a signing key as the seal key", registry: "r/d", deltaKey: signer, sealed: signer, wantErr: "-delta-seal-key"},
		{name: "no state for the signing key", registry: "r/d", stateIsFile: true, wantErr: "-delta-key: "},
		{name: "no state for the seal key", registry: "r/d", deltaKey: signer, stateIsFile: true, wantErr: "-delta-seal-key: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			if tc.stateIsFile {
				if err := os.WriteFile(state, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := agent.Config{StateDir: state, DeltaRegistry: tc.registry, DeltaKey: tc.deltaKey, DeltaTrust: tc.trust, DeltaSealKey: tc.sealed}
			k, err := c.LoadDeltaKeys()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadDeltaKeys: %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.registry == "" {
				if k.Signer != nil || k.Seal != nil {
					t.Fatalf("keys without a registry: %+v", k)
				}
				if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("state touched without a registry: %v", err)
				}
				return
			}
			if len(k.Trust) != tc.wantTrust {
				t.Fatalf("trusts %d keys, want %d", len(k.Trust), tc.wantTrust)
			}
			for _, kk := range []struct{ got, want, file string }{
				{k.Signer.KeyID, tc.wantSigner, "delta-key.json"},
				{k.Seal.ID, tc.wantSeal, "delta-seal-key.json"},
			} {
				path := filepath.Join(c.PrivateDir(), kk.file)
				if kk.want != "gen" {
					if kk.got != kk.want {
						t.Fatalf("kid %s, want the flag's %s", kk.got, kk.want)
					}
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s generated although a flag named a key", kk.file)
					}
					continue
				}
				if got := mode(t, path); got != 0o600 {
					t.Fatalf("%s mode %v, want 0600", kk.file, got)
				}
			}
			again, err := c.LoadDeltaKeys()
			if err != nil {
				t.Fatal(err)
			}
			if again.Signer.KeyID != k.Signer.KeyID || again.Seal.ID != k.Seal.ID {
				t.Fatal("a second load changed the keys")
			}
		})
	}
}
