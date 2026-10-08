package kube_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// seen is one request the test server received.
type seen struct {
	method, path, accept, contentType, auth, body string
}

// roundTrip is an http.RoundTripper from a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestClient checks the request each client call sends and what it makes
// of the answer.
func TestClient(t *testing.T) {
	ctx := context.Background()
	type obj struct {
		Name string `json:"name"`
	}
	cases := []struct {
		name string
		// answer is the server's handler. Nil answers 200 {"name":"x"}.
		answer func(w http.ResponseWriter, r *http.Request)
		// setup adjusts the client. token is the path of a token file
		// holding " tok\n".
		setup func(c *kube.Client, token string, srv *httptest.Server)
		call  func(c *kube.Client) (any, error)
		want  *seen // the request, or nil when none must arrive
		check func(t *testing.T, got any, err error)
	}{
		{name: "Get sends the bearer token, trimmed, and decodes the object",
			call: func(c *kube.Client) (any, error) {
				var o obj
				err := c.Get(ctx, "/api/v1/namespaces/ns/pods/p", &o)
				return o, err
			},
			want: &seen{method: "GET", path: "/api/v1/namespaces/ns/pods/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, got any, err error) {
				if err != nil || got.(obj).Name != "x" {
					t.Fatalf("Get = %+v, %v", got, err)
				}
			}},
		{name: "a base with a trailing slash is joined without a double slash",
			setup: func(c *kube.Client, _ string, _ *httptest.Server) { c.Base += "/" },
			call:  func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/api/v1/namespaces", nil) },
			want:  &seen{method: "GET", path: "/api/v1/namespaces", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				if err != nil {
					t.Fatal(err)
				}
			}},
		{name: "no token file sends no Authorization",
			setup: func(c *kube.Client, _ string, _ *httptest.Server) { c.TokenFile = "" },
			call:  func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/x", nil) },
			want:  &seen{method: "GET", path: "/x", accept: "application/json"},
			check: func(t *testing.T, _ any, err error) {
				if err != nil {
					t.Fatal(err)
				}
			}},
		{name: "an unreadable token file is an error and sends nothing",
			setup: func(c *kube.Client, token string, _ *httptest.Server) { c.TokenFile = token + ".missing" },
			call:  func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/x", nil) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "kube: token") {
					t.Fatalf("err = %v, want the token error", err)
				}
			}},
		{name: "Create posts the object as JSON and decodes what was created",
			call: func(c *kube.Client) (any, error) {
				var o obj
				err := c.Create(ctx, "/api/v1/namespaces/ns/secrets", map[string]string{"name": "s"}, &o)
				return o, err
			},
			want: &seen{method: "POST", path: "/api/v1/namespaces/ns/secrets", accept: "application/json",
				contentType: "application/json", auth: "Bearer tok", body: `{"name":"s"}`},
			check: func(t *testing.T, got any, err error) {
				if err != nil || got.(obj).Name != "x" {
					t.Fatalf("Create = %+v, %v", got, err)
				}
			}},
		{name: "Create of an object that does not marshal sends nothing",
			call: func(c *kube.Client) (any, error) { return nil, c.Create(ctx, "/x", make(chan int), nil) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "unsupported type") {
					t.Fatalf("err = %v, want the marshal error", err)
				}
			}},
		{name: "Delete sends DELETE without a body",
			call: func(c *kube.Client) (any, error) { return nil, c.Delete(ctx, "/api/v1/namespaces/ns/pods/p") },
			want: &seen{method: "DELETE", path: "/api/v1/namespaces/ns/pods/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				if err != nil {
					t.Fatal(err)
				}
			}},
		{name: "PatchStrategic sends a strategic merge patch",
			call: func(c *kube.Client) (any, error) {
				return nil, c.PatchStrategic(ctx, "/p/status", map[string]any{"status": map[string]any{"phase": "Running"}})
			},
			want: &seen{method: "PATCH", path: "/p/status", accept: "application/json", contentType: "application/strategic-merge-patch+json",
				auth: "Bearer tok", body: `{"status":{"phase":"Running"}}`},
			check: func(t *testing.T, _ any, err error) {
				if err != nil {
					t.Fatal(err)
				}
			}},
		{name: "PatchMerge sends a JSON merge patch",
			call: func(c *kube.Client) (any, error) { return nil, c.PatchMerge(ctx, "/s", map[string]any{"a": nil}) },
			want: &seen{method: "PATCH", path: "/s", accept: "application/json", contentType: "application/merge-patch+json",
				auth: "Bearer tok", body: `{"a":null}`},
			check: func(t *testing.T, _ any, err error) {
				if err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a patch that does not marshal sends nothing",
			call: func(c *kube.Client) (any, error) { return nil, c.PatchMerge(ctx, "/s", func() {}) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "unsupported type") {
					t.Fatalf("err = %v, want the marshal error", err)
				}
			}},
		{name: "a 404 Status is a StatusError with the reason and message",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(404)
				_, _ = io.WriteString(w, `{"kind":"Status","reason":"NotFound","message":"pods \"p\" not found","code":404}`)
			},
			call: func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			want: &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				var se *kube.StatusError
				if !errors.As(err, &se) || se.Code != 404 || se.Reason != "NotFound" || se.Body != `pods "p" not found` {
					t.Fatalf("err = %#v", err)
				}
				if !kube.IsNotFound(err) || kube.IsConflict(err) || err.Error() != `kube: 404 pods "p" not found` {
					t.Fatalf("err %q: IsNotFound %v, IsConflict %v", err, kube.IsNotFound(err), kube.IsConflict(err))
				}
			}},
		{name: "a 409 is a conflict",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(409)
				_, _ = io.WriteString(w, `{"reason":"AlreadyExists","message":"exists"}`)
			},
			call: func(c *kube.Client) (any, error) { return nil, c.Create(ctx, "/p", obj{}, nil) },
			want: &seen{method: "POST", path: "/p", accept: "application/json", contentType: "application/json", auth: "Bearer tok", body: `{"name":""}`},
			check: func(t *testing.T, _ any, err error) {
				if !kube.IsConflict(err) || kube.IsNotFound(err) {
					t.Fatalf("err = %v, want a conflict", err)
				}
			}},
		{name: "an error body that is not a Status is kept as it is",
			answer: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "upstream down", http.StatusBadGateway) },
			call:   func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			want:   &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				var se *kube.StatusError
				if !errors.As(err, &se) || se.Code != 502 || se.Body != "upstream down\n" || se.Reason != "" {
					t.Fatalf("err = %#v", err)
				}
			}},
		{name: "a JSON error body without a message is kept as it is",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(500)
				_, _ = io.WriteString(w, `{"reason":"InternalError"}`)
			},
			call: func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			want: &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				var se *kube.StatusError
				if !errors.As(err, &se) || se.Body != `{"reason":"InternalError"}` || se.Reason != "" {
					t.Fatalf("err = %#v", err)
				}
			}},
		{name: "an empty success leaves the destination untouched",
			answer: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) },
			call: func(c *kube.Client) (any, error) {
				o := obj{Name: "before"}
				err := c.Get(ctx, "/p", &o)
				return o, err
			},
			want: &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, got any, err error) {
				if err != nil || got.(obj).Name != "before" {
					t.Fatalf("Get = %+v, %v", got, err)
				}
			}},
		{name: "a success that is not JSON is an error",
			answer: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>") },
			call:   func(c *kube.Client) (any, error) { var o obj; return nil, c.Get(ctx, "/p", &o) },
			want:   &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "invalid character") {
					t.Fatalf("err = %v, want a decode error", err)
				}
			}},
		{name: "an answer is read up to 8 MiB",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"name":"`+strings.Repeat("a", 8<<20)+`"}`)
			},
			call: func(c *kube.Client) (any, error) { var o obj; return nil, c.Get(ctx, "/p", &o) },
			want: &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON") {
					t.Fatalf("err = %v, want the cut answer's decode error", err)
				}
			}},
		{name: "an answer cut short is an error",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					panic(err)
				}
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"na")
				_ = buf.Flush()
				_ = conn.Close()
			},
			call: func(c *kube.Client) (any, error) { var o obj; return nil, c.Get(ctx, "/p", &o) },
			want: &seen{method: "GET", path: "/p", accept: "application/json", auth: "Bearer tok"},
			check: func(t *testing.T, _ any, err error) {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("err = %v, want unexpected EOF", err)
				}
			}},
		{name: "an API server that is down is an error that is neither kind",
			setup: func(_ *kube.Client, _ string, srv *httptest.Server) { srv.Close() },
			call:  func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || kube.IsNotFound(err) || kube.IsConflict(err) {
					t.Fatalf("err = %v, want a transport error", err)
				}
			}},
		{name: "a base that is not a URL is an error",
			setup: func(c *kube.Client, _ string, _ *httptest.Server) { c.Base = "http://bad\x7f" },
			call:  func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || !strings.Contains(err.Error(), "invalid control character") {
					t.Fatalf("err = %v, want the URL error", err)
				}
			}},
		{name: "an ended context is an error and sends nothing",
			call: func(c *kube.Client) (any, error) {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return nil, c.Get(cctx, "/p", nil)
			},
			check: func(t *testing.T, _ any, err error) {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
			}},
		{name: "the client's own HTTP client is the one used",
			setup: func(c *kube.Client, _ string, _ *httptest.Server) {
				c.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 418, Body: io.NopCloser(strings.NewReader(`{"message":"teapot"}`)), Request: r}, nil
				})}
			},
			call: func(c *kube.Client) (any, error) { return nil, c.Get(ctx, "/p", nil) },
			check: func(t *testing.T, _ any, err error) {
				if err == nil || err.Error() != "kube: 418 teapot" {
					t.Fatalf("err = %v, want the transport's answer", err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var got []seen
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				got = append(got, seen{method: r.Method, path: r.URL.Path, accept: r.Header.Get("Accept"),
					contentType: r.Header.Get("Content-Type"), auth: r.Header.Get("Authorization"), body: string(b)})
				mu.Unlock()
				if tc.answer != nil {
					tc.answer(w, r)
					return
				}
				_, _ = io.WriteString(w, `{"name":"x"}`)
			}))
			t.Cleanup(srv.Close)
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte(" tok\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			c := &kube.Client{Base: srv.URL, TokenFile: token}
			if tc.setup != nil {
				tc.setup(c, token, srv)
			}
			res, err := tc.call(c)
			tc.check(t, res, err)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case tc.want == nil && len(got) != 0:
				t.Fatalf("requests = %+v, want none", got)
			case tc.want != nil && (len(got) != 1 || got[0] != *tc.want):
				t.Fatalf("requests = %+v, want [%+v]", got, *tc.want)
			}
		})
	}
}

// TestErrorKinds checks IsNotFound and IsConflict through wrapping.
func TestErrorKinds(t *testing.T) {
	cases := []struct {
		name               string
		err                error
		notFound, conflict bool
	}{
		{name: "nil is neither", err: nil},
		{name: "a plain error is neither", err: errors.New("x")},
		{name: "a 404", err: &kube.StatusError{Code: 404}, notFound: true},
		{name: "a wrapped 404", err: fmt.Errorf("get pod: %w", &kube.StatusError{Code: 404}), notFound: true},
		{name: "a wrapped 409", err: fmt.Errorf("create: %w", &kube.StatusError{Code: 409}), conflict: true},
		{name: "a 500 is neither", err: &kube.StatusError{Code: 500}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kube.IsNotFound(tc.err); got != tc.notFound {
				t.Fatalf("IsNotFound = %v, want %v", got, tc.notFound)
			}
			if got := kube.IsConflict(tc.err); got != tc.conflict {
				t.Fatalf("IsConflict = %v, want %v", got, tc.conflict)
			}
		})
	}
}
