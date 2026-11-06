package artifact

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// useClients points the package's clients at base, a transport that
// trusts the test servers, until the test ends.
func useClients(t *testing.T, base http.RoundTripper) {
	t.Helper()
	oldTLS, oldPlain := tlsClient, plainClient
	tlsClient, plainClient = newClient(base, false), newClient(base, true)
	t.Cleanup(func() { tlsClient, plainClient = oldTLS, oldPlain })
}

// TestClientsKeepDefaults holds both clients to oras-go's default header,
// token cache and retries, and the default client to no policy of ours.
func TestClientsKeepDefaults(t *testing.T) {
	cases := []struct {
		name   string
		client *auth.Client
	}{
		{name: "the TLS client", client: tlsClient},
		{name: "the plain HTTP client", client: plainClient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !reflect.DeepEqual(c.client.Header, auth.DefaultClient.Header) {
				t.Fatalf("header = %v, want %v", c.client.Header, auth.DefaultClient.Header)
			}
			if c.client.Cache != auth.DefaultClient.Cache {
				t.Fatal("the client does not share the default token cache")
			}
			if _, ok := c.client.Client.Transport.(*retry.Transport); !ok {
				t.Fatalf("transport = %T, want *retry.Transport", c.client.Client.Transport)
			}
			if auth.DefaultClient.Client.CheckRedirect != nil {
				t.Fatal("the default client has a redirect policy")
			}
		})
	}
}

// TestRegistryRedirects walks one request along a chain of servers, each
// redirecting to the next with a query a refusal must not repeat. How the
// registry was named picks the policy, so a chain is followed or refused
// by its first server and the hop in question.
func TestRegistryRedirects(t *testing.T) {
	const (
		registry = "registry" // TLS
		other    = "other"    // TLS, another origin
		plain    = "plain"    // plain http

		leavesTLS = "redirect leaves TLS"
		tooMany   = "too many redirects"
	)
	cases := []struct {
		name  string
		chain []string // the servers a request walks, the registry first
		loop  bool     // the last server sends it back to the first
		sent  int32    // requests that reach a server
		want  string   // the refusal, empty when the chain is followed
	}{
		{name: "a TLS registry that redirects to plain http is refused", chain: []string{registry, plain}, sent: 1, want: leavesTLS},
		{name: "a TLS hop that redirects to plain http is refused", chain: []string{registry, other, plain}, sent: 2, want: leavesTLS},
		{name: "a TLS registry that redirects to another TLS host is followed", chain: []string{registry, other}, sent: 2},
		{name: "a chain as long as the bound is followed", chain: slices.Repeat([]string{registry}, maxRedirects+1), sent: maxRedirects + 1},
		{name: "a redirect loop is refused at the bound", chain: []string{registry, other}, loop: true, sent: maxRedirects + 1, want: tooMany},
		{name: "a registry named with http:// that redirects to plain http is followed", chain: []string{plain, plain}, sent: 2},
		{name: "a registry named with http:// that redirects to TLS is followed", chain: []string{plain, registry}, sent: 2},
		{name: "a TLS hop from a registry named with http:// may return to plain http", chain: []string{plain, registry, plain}, sent: 3},
		{name: "a redirect loop from a registry named with http:// is refused at the bound", chain: []string{plain}, loop: true, sent: maxRedirects + 1, want: tooMany},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sent atomic.Int32
			urls := map[string]string{}
			walk := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				hop, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				hop++
				if hop == len(c.chain) && !c.loop {
					return
				}
				next := urls[c.chain[hop%len(c.chain)]]
				http.Redirect(w, r, fmt.Sprintf("%s/%d?sig=x", next, hop), http.StatusTemporaryRedirect)
			})
			servers := map[string]*httptest.Server{
				registry: httptest.NewTLSServer(walk),
				other:    httptest.NewTLSServer(walk),
				plain:    httptest.NewServer(walk),
			}
			for name, srv := range servers {
				t.Cleanup(srv.Close)
				urls[name] = srv.URL
			}
			useClients(t, servers[registry].Client().Transport)

			start := urls[c.chain[0]]
			repo, _, err := repository(start + "/r:t")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, start+"/0", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := repo.Client.Do(req)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			} else {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatalf("followed, want %q", c.want)
				}
				if got, want := refusal(err).Error(), "registry "+req.URL.Host+": "+c.want; got != want {
					t.Fatalf("refusal = %q, want %q", got, want)
				}
			}
			if got := sent.Load(); got != c.sent {
				t.Fatalf("%d requests reached a server, want %d", got, c.sent)
			}
		})
	}
}

// TestRegistryCallsRefuseRedirects runs every call that reaches a registry
// against one that redirects off TLS. heads and untag let a call past its
// first request, so each place that returns a registry error is reached.
func TestRegistryCallsRefuseRedirects(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{fileZygote: "zygote", fileConfig: "{}"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resolve := func(ctx context.Context, ref string) error {
		_, _, err := Resolve(ctx, ref)
		return err
	}
	remove := func(ctx context.Context, ref string) error {
		_, err := Delete(ctx, ref)
		return err
	}
	cases := []struct {
		name  string
		call  func(ctx context.Context, ref string) error
		heads bool   // the registry answers a HEAD on the manifest
		untag int    // its answer to a DELETE of the tag, 0 to redirect it
		want  string // how the error starts
	}{
		{name: "Push", want: "artifact: push", call: func(ctx context.Context, ref string) error {
			_, err := Push(ctx, src, ref)
			return err
		}},
		{name: "PushDir", want: "artifact: push", call: func(ctx context.Context, ref string) error {
			_, err := PushDir(ctx, src, ref, ArtifactTypeParent, nil, nil)
			return err
		}},
		{name: "Pull", want: "artifact: pull", call: func(ctx context.Context, ref string) error {
			_, err := Pull(ctx, ref, dst)
			return err
		}},
		{name: "PullDir", want: "artifact: pull", call: func(ctx context.Context, ref string) error {
			_, err := PullDir(ctx, ref, dst)
			return err
		}},
		{name: "Resolve at its HEAD", call: resolve, want: "artifact: resolve"},
		{name: "Resolve at its fetch", call: resolve, heads: true, want: "artifact: resolve"},
		{name: "Delete at its HEAD", call: remove, want: "artifact: delete"},
		{name: "Delete at the tag", call: remove, heads: true, want: "artifact: untag"},
		{name: "Delete at the manifest", call: remove, heads: true, untag: http.StatusMethodNotAllowed, want: "artifact: delete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var offTLS atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				offTLS.Add(1)
			}))
			t.Cleanup(plain.Close)
			reg := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case c.heads && r.Method == http.MethodHead:
					manifest := ocispec.DescriptorEmptyJSON
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Content-Length", strconv.FormatInt(manifest.Size, 10))
					w.Header().Set("Docker-Content-Digest", manifest.Digest.String())
				case c.untag != 0 && r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/manifests/t"):
					w.WriteHeader(c.untag)
				default:
					http.Redirect(w, r, plain.URL+"/blob?sig=x", http.StatusTemporaryRedirect)
				}
			}))
			t.Cleanup(reg.Close)
			useClients(t, reg.Client().Transport)

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			err := c.call(ctx, strings.TrimPrefix(reg.URL, "https://")+"/r:t")
			if err == nil {
				t.Fatal("the call succeeded")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, c.want) || !strings.Contains(msg, "redirect leaves TLS") {
				t.Fatalf("error = %q, want it to start %q and say the redirect leaves TLS", msg, c.want)
			}
			if strings.Contains(msg, "sig=") {
				t.Fatalf("error repeats the Location: %q", msg)
			}
			if got := offTLS.Load(); got != 0 {
				t.Fatalf("%d requests left TLS", got)
			}
		})
	}
}
