package artifact_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// middleware wraps the in-process registry to change what it answers.
type middleware func(next http.Handler) http.Handler

// newFaultyRegistry serves go-containerregistry's in-memory registry,
// and returns its host:port. Once arm is called, requests go through mw.
func newFaultyRegistry(t *testing.T, mw middleware) (host string, arm func()) {
	t.Helper()
	plain := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	faulty := plain
	if mw != nil {
		faulty = mw(plain)
	}
	var armed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() {
			faulty.ServeHTTP(w, r)
			return
		}
		plain.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), func() { armed.Store(true) }
}

// matches reports whether r is method on a manifest (kind "manifest")
// or blob (kind "blob") whose reference starts with prefix.
func matches(r *http.Request, method, kind, prefix string) bool {
	if r.Method != method {
		return false
	}
	_, ref, ok := strings.Cut(r.URL.Path, "/"+kind+"s/")
	return ok && strings.HasPrefix(ref, prefix)
}

// answer makes matching requests fail with status.
func answer(method, kind, prefix string, status int) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matches(r, method, kind, prefix) {
				w.WriteHeader(status)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hangUp drops the connection on matching requests.
func hangUp(method, kind, prefix string) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matches(r, method, kind, prefix) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// dropsTagWithManifest makes a delete by digest drop tag too, as
// registry:2 does (go-containerregistry keeps tag entries).
func dropsTagWithManifest(tag string) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if matches(r, http.MethodDelete, "manifest", "sha256:") {
				untag := r.Clone(r.Context())
				untag.URL.Path = r.URL.Path[:strings.LastIndex(r.URL.Path, "/")+1] + tag
				next.ServeHTTP(httptest.NewRecorder(), untag)
			}
		})
	}
}

// corrupt flips the last byte of every manifest the registry serves.
func corrupt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !matches(r, http.MethodGet, "manifest", "") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		b := rec.Body.Bytes()
		if len(b) > 0 {
			b[len(b)-1] ^= 1
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(b)
	})
}

func chain(mws ...middleware) middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			next = mws[i](next)
		}
		return next
	}
}

// pushDelta pushes a one-file directory artifact to reg/r:t.
func pushDelta(t *testing.T, reg string) string {
	t.Helper()
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pages-1.img"), "pages")
	d, err := artifact.PushDir(context.Background(), src, reg+"/r:t", artifact.ArtifactTypeDelta, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDelete runs Delete against registries that delete tags, refuse to,
// or fail, and checks what still resolves afterwards.
func TestDelete(t *testing.T) {
	cases := []struct {
		name string
		mw   middleware
		ref  string // under the registry, r:t by default
		want string // a substring of the error, "" for success
		// gone and kept are references under the registry that must and
		// must not resolve afterwards. "@" stands for r@<digest>.
		gone, kept []string
	}{
		{name: "a tag goes, and the manifest with it", gone: []string{"r:t", "@"}},
		{name: "a digest goes", ref: "@", gone: []string{"@"}},
		{name: "a missing tag is already gone", ref: "r:missing", kept: []string{"r:t"}},
		{name: "a missing repository is already gone", ref: "other:t", kept: []string{"r:t"}},
		{name: "a registry that refuses to untag (400) drops the tag with the manifest",
			mw: chain(answer(http.MethodDelete, "manifest", "t", http.StatusBadRequest), dropsTagWithManifest("t")), gone: []string{"r:t", "@"}},
		{name: "a registry that does not allow untag (405) drops the tag with the manifest",
			mw: chain(answer(http.MethodDelete, "manifest", "t", http.StatusMethodNotAllowed), dropsTagWithManifest("t")), gone: []string{"r:t", "@"}},
		{name: "an untag that finds nothing (404) is fine",
			mw: chain(answer(http.MethodDelete, "manifest", "t", http.StatusNotFound), dropsTagWithManifest("t")), gone: []string{"r:t", "@"}},
		{name: "a registry that deletes neither way is an error",
			mw: answer(http.MethodDelete, "manifest", "t", http.StatusBadRequest), want: "does not support deletion"},
		{name: "an untag that fails is an error",
			mw: answer(http.MethodDelete, "manifest", "t", http.StatusInternalServerError), want: "untag", kept: []string{"r:t", "@"}},
		{name: "an untag whose connection drops is an error",
			mw: hangUp(http.MethodDelete, "manifest", "t"), want: "untag", kept: []string{"r:t", "@"}},
		{name: "a manifest delete that fails is an error",
			mw: answer(http.MethodDelete, "manifest", "sha256:", http.StatusForbidden), want: "artifact: delete", kept: []string{"@"}},
		{name: "a manifest delete that finds nothing is fine",
			mw: answer(http.MethodDelete, "manifest", "sha256:", http.StatusNotFound), gone: []string{"r:t"}, kept: []string{"@"}},
		{name: "a resolve that fails is an error",
			mw: answer(http.MethodHead, "manifest", "", http.StatusForbidden), want: "403"},
		{name: "a reference that does not parse", ref: "UPPER:t", want: "UPPER"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			reg, arm := newFaultyRegistry(t, c.mw)
			digest := pushDelta(t, reg)
			arm()
			full := func(ref string) string {
				if ref == "@" {
					return reg + "/r@" + digest
				}
				return reg + "/" + ref
			}
			ref := "r:t"
			if c.ref != "" {
				ref = c.ref
			}
			err := artifact.Delete(ctx, full(ref), true)
			if c.want == "" && err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("Delete = %v, want an error about %q", err, c.want)
			}
			for _, list := range []struct {
				refs  []string
				found bool
			}{{c.gone, false}, {c.kept, true}} {
				for _, r := range list.refs {
					_, found, err := artifact.Resolve(ctx, full(r), true)
					if err != nil || found != list.found {
						t.Fatalf("after delete, %s found = %v (%v), want %v", r, found, err, list.found)
					}
				}
			}
		})
	}
}

// TestResolveRegistry covers Resolve against registries that fail or
// serve something other than what they were asked for.
func TestResolveRegistry(t *testing.T) {
	notJSON := func(t *testing.T, reg string) {
		req, err := http.NewRequest(http.MethodPut, "http://"+reg+"/v2/r/manifests/t", bytes.NewReader([]byte("not json")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", ocispec.MediaTypeImageManifest)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT manifest: %s", resp.Status)
		}
	}
	cases := []struct {
		name  string
		mw    middleware
		setup func(t *testing.T, reg string)
		ref   string
		found bool
		ok    bool
	}{
		{name: "a pushed tag is found", ref: "r:t", found: true, ok: true},
		{name: "a missing tag is not found", ref: "r:missing", ok: true},
		{name: "a missing repository is not found", ref: "nobody:t", ok: true},
		{name: "a resolve that fails is an error", ref: "r:t", mw: answer(http.MethodHead, "manifest", "", http.StatusForbidden)},
		{name: "a fetch that fails is an error", ref: "r:t", mw: answer(http.MethodGet, "manifest", "", http.StatusForbidden)},
		{name: "a manifest that does not match its digest is an error", ref: "r:t", mw: corrupt},
		{name: "a manifest that is not JSON is an error", ref: "r:t", setup: notJSON},
		{name: "a reference that does not parse", ref: "UPPER:t"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, arm := newFaultyRegistry(t, c.mw)
			if c.setup != nil {
				c.setup(t, reg)
			} else {
				pushDelta(t, reg)
			}
			arm()
			loc, found, err := artifact.Resolve(context.Background(), reg+"/"+c.ref, true)
			if c.ok != (err == nil) || found != c.found {
				t.Fatalf("Resolve = %+v, %v, %v; want ok %v, found %v", loc, found, err, c.ok, c.found)
			}
			if found && (loc.ArtifactType != artifact.ArtifactTypeDelta || len(loc.Files) != 1 || loc.Files[0].Name != "pages-1.img") {
				t.Fatalf("Resolve = %+v", loc)
			}
		})
	}
}

// TestDirRegistryTransfers covers PushDir and PullDir against a registry.
func TestDirRegistryTransfers(t *testing.T) {
	created := "2001-02-03T04:05:06Z"
	cases := []struct {
		name string
		mw   middleware
		op   string // push or pull
		// ref is under the registry. For a pull, r:t holds the pushed
		// artifact.
		ref     string
		ann     map[string]string
		noSrc   bool
		dstFile bool // the pull destination is under a regular file
		ok      bool
	}{
		{name: "a push without a tag is reachable by its digest", op: "push", ref: "r", ok: true},
		{name: "a push keeps the created time it is given", op: "push", ref: "r:c",
			ann: map[string]string{ocispec.AnnotationCreated: created}, ok: true},
		{name: "a push needs its source", op: "push", ref: "r:t", noSrc: true},
		{name: "a push to a reference that does not parse", op: "push", ref: "UPPER:t"},
		{name: "a push the registry refuses", op: "push", ref: "r:t",
			mw: answer(http.MethodPost, "blob", "", http.StatusForbidden)},
		{name: "a pull restores the files", op: "pull", ref: "r:t", ok: true},
		{name: "a pull of a missing tag", op: "pull", ref: "r:missing"},
		{name: "a pull from a reference that does not parse", op: "pull", ref: "UPPER:t"},
		{name: "a pull into a destination under a file", op: "pull", ref: "r:t", dstFile: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			reg, arm := newFaultyRegistry(t, c.mw)
			arm() // pushes are what fail here
			src := t.TempDir()
			writeFile(t, filepath.Join(src, "pages-1.img"), "pages")
			writeFile(t, filepath.Join(src, "dump.log"), "noise")
			switch c.op {
			case "push":
				if c.noSrc {
					src = filepath.Join(src, "missing")
				}
				d, err := artifact.PushDir(ctx, src, reg+"/"+c.ref, artifact.ArtifactTypeDelta, c.ann, nil, true)
				if c.ok != (err == nil) {
					t.Fatalf("PushDir = %s, %v; want ok %v", d, err, c.ok)
				}
				if !c.ok {
					return
				}
				repo, _, _ := strings.Cut(c.ref, ":")
				loc, found, err := artifact.Resolve(ctx, reg+"/"+repo+"@"+d, true)
				if err != nil || !found || loc.Digest != d {
					t.Fatalf("Resolve by digest = %+v, %v, %v", loc, found, err)
				}
				if want := c.ann[ocispec.AnnotationCreated]; want != "" && loc.Annotations[ocispec.AnnotationCreated] != want {
					t.Fatalf("created = %q, want %q", loc.Annotations[ocispec.AnnotationCreated], want)
				}
			case "pull":
				pushed, err := artifact.PushDir(ctx, src, reg+"/r:t", artifact.ArtifactTypeDelta, nil, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				root := t.TempDir()
				dst := filepath.Join(root, "dst")
				if c.dstFile {
					writeFile(t, filepath.Join(root, "file"), "")
					dst = filepath.Join(root, "file", "dst")
				}
				d, err := artifact.PullDir(ctx, reg+"/"+c.ref, dst, true)
				if c.ok != (err == nil) {
					t.Fatalf("PullDir = %s, %v; want ok %v", d, err, c.ok)
				}
				if !c.ok {
					return
				}
				if d != pushed {
					t.Fatalf("PullDir digest = %s, want %s", d, pushed)
				}
				if b, err := os.ReadFile(filepath.Join(dst, "pages-1.img")); err != nil || string(b) != "pages" {
					t.Fatalf("pages-1.img = %q, %v", b, err)
				}
				if _, err := os.Stat(filepath.Join(dst, "dump.log")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a log travelled: %v", err)
				}
			}
		})
	}
}

func TestRepository(t *testing.T) {
	cases := []struct {
		name, ref, registry, repo, target string
		plain                             bool
		bad                               bool
	}{
		{name: "a tag", ref: "reg.example:5000/a/b:v1", registry: "reg.example:5000", repo: "a/b", target: "v1", plain: true},
		{name: "a digest", ref: "reg.example/a@sha256:" + strings.Repeat("ab", 32), registry: "reg.example", repo: "a",
			target: "sha256:" + strings.Repeat("ab", 32)},
		{name: "a port and no tag", ref: "reg.example:5000/a", registry: "reg.example:5000", repo: "a"},
		{name: "a name the registry cannot hold", ref: "reg.example/UPPER:v1", bad: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo, target, err := artifact.Repository(c.ref, c.plain)
			if c.bad {
				if err == nil {
					t.Fatalf("Repository(%q) accepted it", c.ref)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%s %s %s %v", repo.Reference.Registry, repo.Reference.Repository, target, repo.PlainHTTP)
			if want := fmt.Sprintf("%s %s %s %v", c.registry, c.repo, c.target, c.plain); got != want {
				t.Fatalf("Repository(%q) = %s, want %s", c.ref, got, want)
			}
		})
	}
}
