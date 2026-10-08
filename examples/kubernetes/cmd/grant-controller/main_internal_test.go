package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

const cgPath = "/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform"

// getJSON fetches url into dst.
func getJSON(url string, dst any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return json.Unmarshal(b, dst)
}

// TestRun checks the controller command. It covers where its client,
// namespace and key come from, the discovery document and JWKS it serves,
// the reconcile loop it runs, and what stops it from starting.
func TestRun(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })

	cases := []struct {
		name      string
		args      []string
		prep      func(srv *kubetest.Server) // sets the cluster up
		real      bool                       // use the real in-cluster configuration
		nsErr     error                      // what reading this Pod's namespace returns
		wantErr   string
		issuer    string // the issuer discovery must name
		keySecret string // where the signing key must be
	}{
		{name: "an unknown flag is an error", args: []string{"-nope"}, wantErr: "flag provided but not defined: -nope"},
		{name: "outside a cluster is an error", real: true, wantErr: "not in a cluster"},
		{name: "no -namespace and no namespace file is an error", nsErr: errors.New("kube: namespace: gone"), wantErr: "kube: namespace: gone"},
		{name: "a key Secret that cannot be read is an error",
			prep: func(srv *kubetest.Server) {
				srv.Fail("GET", "/api/v1/namespaces/fiberd-system/secrets/grant-issuer-key", 500, 1)
			},
			wantErr: "kube: 500"},
		// A listen failure must stop the controller. Otherwise it would
		// mint grants that no Pod could verify.
		{name: "an address that cannot be listened on is an error", args: []string{"-addr", busy.Addr().String()},
			wantErr: "address already in use"},
		{name: "the defaults: this Pod's namespace, the issuer named after it, the default key Secret",
			issuer: "http://grant-issuer.fiberd-system.svc:8080", keySecret: "/api/v1/namespaces/fiberd-system/secrets/grant-issuer-key"},
		{name: "the flags: namespace, issuer and key Secret as given",
			args:   []string{"-namespace", "issuers", "-issuer", "https://issuer.example", "-key-secret", "k"},
			nsErr:  errors.New("must not be read when -namespace is given"),
			issuer: "https://issuer.example", keySecret: "/api/v1/namespaces/issuers/secrets/k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			t.Cleanup(srv.Close)
			srv.Put(cgPath, map[string]any{"spec": map[string]any{"isolation": "TRUSTED", "pod": map[string]any{"image": "i"}}})
			if tc.prep != nil {
				tc.prep(srv)
			}
			addrs := make(chan net.Addr, 1)
			oldIn, oldNS, oldServing := inCluster, podNamespace, serving
			t.Cleanup(func() { inCluster, podNamespace, serving = oldIn, oldNS, oldServing })
			if tc.real {
				t.Setenv("KUBERNETES_SERVICE_HOST", "")
			} else {
				inCluster = func() (*kube.Client, error) { return &kube.Client{Base: srv.URL()}, nil }
			}
			podNamespace = func() (string, error) {
				if tc.nsErr != nil {
					return "", tc.nsErr
				}
				return "fiberd-system", nil
			}
			serving = func(a net.Addr) { addrs <- a }

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs := flag.NewFlagSet("grant-controller", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			// A later flag wins, so a case's -addr replaces this one.
			args := append([]string{"-addr", "127.0.0.1:0", "-poll", "10ms"}, tc.args...)
			done := make(chan error, 1)
			go func() { done <- run(ctx, fs, args) }()

			if tc.wantErr != "" {
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("run = %v, want %q", err, tc.wantErr)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("run kept going, want the error %q", tc.wantErr)
				}
				return
			}

			var addr net.Addr
			select {
			case addr = <-addrs:
			case err := <-done:
				t.Fatalf("run = %v before serving", err)
			}
			base := "http://" + addr.String()
			var disc struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}
			if err := getJSON(base+"/.well-known/openid-configuration", &disc); err != nil || disc.Issuer != tc.issuer || disc.JWKSURI != tc.issuer+"/openid/v1/jwks" {
				t.Fatalf("discovery = %+v (%v), want issuer %s", disc, err, tc.issuer)
			}
			// The served key is the public half of the one in the Secret.
			var set jose.JSONWebKeySet
			if err := getJSON(base+"/openid/v1/jwks", &set); err != nil || len(set.Keys) != 1 {
				t.Fatalf("jwks = %+v (%v)", set, err)
			}
			sec := srv.Get(tc.keySecret)
			if sec == nil {
				t.Fatalf("no key Secret at %s", tc.keySecret)
			}
			var stored jose.JSONWebKey
			if err := json.Unmarshal([]byte(decodeData(t, sec)), &stored); err != nil || stored.KeyID != set.Keys[0].KeyID || !set.Keys[0].IsPublic() {
				t.Fatalf("served kid %s public %v, stored kid %s (%v)", set.Keys[0].KeyID, set.Keys[0].IsPublic(), stored.KeyID, err)
			}
			// The reconcile loop runs, so the CapacityGrant gets its Pod.
			for deadline := time.Now().Add(10 * time.Second); srv.Get("/api/v1/namespaces/tenant-a/pods/conform-grant") == nil; time.Sleep(5 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the CapacityGrant was never reconciled")
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("run = %v after ctx ended, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("run did not return after ctx ended")
			}
			if _, err := http.Get(base + "/openid/v1/jwks"); err == nil {
				t.Fatal("discovery still served after run returned")
			}
		})
	}
}

// decodeData is the key.json of a Secret as the API server stores it.
func decodeData(t *testing.T, sec map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(sec["data"])
	var data map[string][]byte
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	return string(data["key.json"])
}
