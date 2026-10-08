package kubetest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

const (
	podPath = "/api/v1/namespaces/ns/pods/p"
	cgPath  = "/apis/fiberd.io/v1alpha1/namespaces/ns/capacitygrants/cg"
)

// send makes one raw request and decodes the JSON answer, if any.
func send(t *testing.T, s *kubetest.Server, method, path, contentType, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// at reads a nested field by its keys.
func at(obj map[string]any, keys ...string) any {
	var cur any = obj
	for _, k := range keys {
		m, _ := cur.(map[string]any)
		cur = m[k]
	}
	return cur
}

// names lists the metadata.name of a list's items, in order.
func names(list map[string]any) []string {
	out := []string{}
	items, _ := list["items"].([]any)
	for _, it := range items {
		out = append(out, at(it.(map[string]any), "metadata", "name").(string))
	}
	return out
}

func seedPod(s *kubetest.Server) {
	s.Put(podPath, map[string]any{
		"metadata": map[string]any{"labels": map[string]string{"a": "1", "b": "2"}},
		"spec":     map[string]any{"nodeName": "n1", "containers": []map[string]any{{"name": "agent"}}},
		"status": map[string]any{"phase": "Pending", "conditions": []map[string]any{
			{"type": "Ready", "status": "False"}, {"type": "Other", "status": "True"}}},
	})
}

// TestServer checks each verb the fake API server answers, and the state
// it leaves behind.
func TestServer(t *testing.T) {
	cases := []struct {
		name           string
		seed           func(s *kubetest.Server)
		method, path   string
		ctype, body    string
		code           int
		check          func(t *testing.T, s *kubetest.Server, resp map[string]any)
		wantStatusFrom string // the reason of a Status answer
	}{
		{name: "GET returns a seeded object with its uid, name and namespace filled",
			seed: seedPod, method: "GET", path: podPath, code: 200,
			check: func(t *testing.T, _ *kubetest.Server, resp map[string]any) {
				if got := at(resp, "metadata"); !reflect.DeepEqual(got, map[string]any{
					"name": "p", "namespace": "ns", "uid": "uid-1", "labels": map[string]any{"a": "1", "b": "2"}}) {
					t.Fatalf("metadata = %v", got)
				}
			}},
		{name: "GET of a missing object is a NotFound Status",
			method: "GET", path: podPath, code: 404, wantStatusFrom: "NotFound"},
		{name: "GET of a path that is neither object nor collection is NotFound",
			method: "GET", path: "/healthz", code: 404, wantStatusFrom: "NotFound"},
		{name: "GET of a namespaced collection lists the objects one level below, sorted",
			seed: func(s *kubetest.Server) {
				s.Put("/api/v1/namespaces/ns/pods/b", nil)
				s.Put("/api/v1/namespaces/ns/pods/a", nil)
				s.Put("/api/v1/namespaces/other/pods/c", nil)
				s.Put("/api/v1/namespaces/ns/pods/a/status", nil)
			},
			method: "GET", path: "/api/v1/namespaces/ns/pods/", code: 200,
			check: func(t *testing.T, _ *kubetest.Server, resp map[string]any) {
				if got := names(resp); !reflect.DeepEqual(got, []string{"a", "b"}) {
					t.Fatalf("items = %v, want [a b]", got)
				}
			}},
		{name: "GET of a cluster-wide custom resource list spans namespaces",
			seed: func(s *kubetest.Server) {
				s.Put("/apis/fiberd.io/v1alpha1/namespaces/x/capacitygrants/one", nil)
				s.Put("/apis/fiberd.io/v1alpha1/namespaces/y/capacitygrants/two", nil)
				s.Put("/apis/fiberd.io/v1alpha1/namespaces/y/others/three", nil)
			},
			method: "GET", path: "/apis/fiberd.io/v1alpha1/capacitygrants", code: 200,
			check: func(t *testing.T, _ *kubetest.Server, resp map[string]any) {
				if got := names(resp); !reflect.DeepEqual(got, []string{"one", "two"}) {
					t.Fatalf("items = %v, want [one two]", got)
				}
			}},
		{name: "GET of an empty collection is an empty list",
			method: "GET", path: "/api/v1/namespaces", code: 200,
			check: func(t *testing.T, _ *kubetest.Server, resp map[string]any) {
				if items, ok := resp["items"].([]any); !ok || len(items) != 0 {
					t.Fatalf("items = %v, want []", resp["items"])
				}
			}},
		{name: "POST creates the object under the collection, with a uid and its namespace",
			method: "POST", path: "/api/v1/namespaces/ns/secrets", ctype: "application/json",
			body: `{"metadata":{"name":"s"},"data":{"k":"dg=="}}`, code: 201,
			check: func(t *testing.T, s *kubetest.Server, resp map[string]any) {
				if at(resp, "metadata", "uid") != "uid-1" {
					t.Fatalf("created = %v", resp)
				}
				got := s.Get("/api/v1/namespaces/ns/secrets/s")
				if at(got, "metadata", "namespace") != "ns" || at(got, "data", "k") != "dg==" {
					t.Fatalf("stored = %v", got)
				}
			}},
		{name: "POST of an existing name is a Conflict",
			seed: seedPod, method: "POST", path: "/api/v1/namespaces/ns/pods", body: `{"metadata":{"name":"p"}}`,
			code: 409, wantStatusFrom: "AlreadyExists"},
		{name: "POST without a name is Invalid",
			method: "POST", path: "/api/v1/namespaces/ns/pods", body: `{"metadata":{}}`,
			code: 422, wantStatusFrom: "Invalid"},
		// A regression test: the handler type-asserted metadata without
		// checking, and an object without one dropped the connection.
		{name: "POST without metadata is Invalid",
			method: "POST", path: "/api/v1/namespaces/ns/pods", body: `{"kind":"Pod"}`,
			code: 422, wantStatusFrom: "Invalid"},
		{name: "POST of a body that is not JSON is a BadRequest",
			method: "POST", path: "/api/v1/namespaces/ns/pods", body: `{`, code: 400},
		{name: "a merge PATCH merges maps, deletes nulls and replaces lists",
			seed: seedPod, method: "PATCH", path: podPath, ctype: "application/merge-patch+json",
			body: `{"metadata":{"labels":{"a":null,"c":"3"}},"spec":{"containers":[{"name":"new"}]}}`, code: 200,
			check: func(t *testing.T, s *kubetest.Server, _ map[string]any) {
				got := s.Get(podPath)
				if l := at(got, "metadata", "labels"); !reflect.DeepEqual(l, map[string]any{"b": "2", "c": "3"}) {
					t.Fatalf("labels = %v", l)
				}
				if c := at(got, "spec", "containers"); !reflect.DeepEqual(c, []any{map[string]any{"name": "new"}}) {
					t.Fatalf("containers = %v", c)
				}
				if at(got, "spec", "nodeName") != "n1" {
					t.Fatalf("an untouched field changed: %v", got)
				}
			}},
		{name: "a strategic PATCH merges a list by key and appends the rest",
			seed: seedPod, method: "PATCH", path: podPath + "/status", ctype: "application/strategic-merge-patch+json",
			body: `{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"New","status":"True"},"bare"]}}`, code: 200,
			check: func(t *testing.T, s *kubetest.Server, _ map[string]any) {
				want := []any{
					map[string]any{"type": "Ready", "status": "True"},
					map[string]any{"type": "Other", "status": "True"},
					map[string]any{"type": "New", "status": "True"},
					"bare",
				}
				if got := at(s.Get(podPath), "status", "conditions"); !reflect.DeepEqual(got, want) {
					t.Fatalf("conditions = %v, want %v", got, want)
				}
			}},
		{name: "a strategic PATCH merges list items keyed by name",
			seed: seedPod, method: "PATCH", path: podPath, ctype: "application/strategic-merge-patch+json",
			body: `{"spec":{"containers":[{"name":"agent","image":"i"},{"image":"keyless"}]}}`, code: 200,
			check: func(t *testing.T, s *kubetest.Server, _ map[string]any) {
				want := []any{map[string]any{"name": "agent", "image": "i"}, map[string]any{"image": "keyless"}}
				if got := at(s.Get(podPath), "spec", "containers"); !reflect.DeepEqual(got, want) {
					t.Fatalf("containers = %v, want %v", got, want)
				}
			}},
		{name: "a PATCH of the status subresource changes the status only",
			seed: seedPod, method: "PATCH", path: podPath + "/status", ctype: "application/merge-patch+json",
			body: `{"spec":{"nodeName":"n2"},"status":{"phase":"Running"}}`, code: 200,
			check: func(t *testing.T, s *kubetest.Server, _ map[string]any) {
				got := s.Get(podPath)
				if at(got, "spec", "nodeName") != "n1" || at(got, "status", "phase") != "Running" {
					t.Fatalf("pod = %v", got)
				}
			}},
		// A regression test: a status patch without a status deleted it.
		{name: "a PATCH of the status subresource without a status leaves it",
			seed: seedPod, method: "PATCH", path: podPath + "/status", ctype: "application/merge-patch+json",
			body: `{"metadata":{"labels":{"x":"y"}}}`, code: 200,
			check: func(t *testing.T, s *kubetest.Server, _ map[string]any) {
				got := s.Get(podPath)
				if at(got, "status", "phase") != "Pending" || at(got, "metadata", "labels", "x") != nil {
					t.Fatalf("pod = %v", got)
				}
			}},
		{name: "a PATCH of a missing object is NotFound",
			method: "PATCH", path: podPath + "/status", body: `{}`, code: 404, wantStatusFrom: "NotFound"},
		{name: "a PATCH that is not JSON is a BadRequest",
			seed: seedPod, method: "PATCH", path: podPath, body: `nope`, code: 400},
		{name: "DELETE takes the object and, through owner references, its dependents' dependents",
			seed: func(s *kubetest.Server) {
				s.Put(cgPath, map[string]any{"metadata": map[string]any{"uid": "cg-uid"}})
				s.Put(podPath, map[string]any{"metadata": map[string]any{"uid": "pod-uid",
					"ownerReferences": []map[string]any{{"uid": "cg-uid"}}}})
				s.Put("/api/v1/namespaces/ns/configmaps/of-pod", map[string]any{"metadata": map[string]any{
					"ownerReferences": []map[string]any{{"uid": "someone"}, {"uid": "pod-uid"}}}})
				s.Put("/api/v1/namespaces/ns/configmaps/unrelated", map[string]any{"metadata": map[string]any{
					"ownerReferences": []any{"not-a-ref"}}})
			},
			method: "DELETE", path: cgPath, code: 200,
			check: func(t *testing.T, s *kubetest.Server, resp map[string]any) {
				if resp["status"] != "Success" {
					t.Fatalf("answer = %v", resp)
				}
				for _, p := range []string{cgPath, podPath, "/api/v1/namespaces/ns/configmaps/of-pod"} {
					if s.Get(p) != nil {
						t.Fatalf("%s survived its owner's deletion", p)
					}
				}
				if s.Get("/api/v1/namespaces/ns/configmaps/unrelated") == nil {
					t.Fatal("an unrelated object was deleted")
				}
			}},
		{name: "DELETE of a missing object is NotFound",
			method: "DELETE", path: podPath, code: 404, wantStatusFrom: "NotFound"},
		{name: "another verb is not allowed",
			seed: seedPod, method: "PUT", path: podPath, body: `{}`, code: 405},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New()
			t.Cleanup(s.Close)
			if tc.seed != nil {
				tc.seed(s)
			}
			code, resp := send(t, s, tc.method, tc.path, tc.ctype, tc.body)
			if code != tc.code {
				t.Fatalf("%s %s = %d (%v), want %d", tc.method, tc.path, code, resp, tc.code)
			}
			if tc.wantStatusFrom != "" && (resp["kind"] != "Status" || resp["reason"] != tc.wantStatusFrom) {
				t.Fatalf("answer = %v, want a %s Status", resp, tc.wantStatusFrom)
			}
			if tc.check != nil {
				tc.check(t, s, resp)
			}
		})
	}
}

// TestServerState checks the methods a test drives the server with
// directly: seeding, reading, changing, failing and the request log.
func TestServerState(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, s *kubetest.Server)
	}{
		{"Get of a missing object is nil", func(t *testing.T, s *kubetest.Server) {
			if got := s.Get(podPath); got != nil {
				t.Fatalf("Get = %v, want nil", got)
			}
		}},
		{"Get returns a copy, so changing it changes nothing stored", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			s.Get(podPath)["spec"].(map[string]any)["nodeName"] = "changed"
			if got := at(s.Get(podPath), "spec", "nodeName"); got != "n1" {
				t.Fatalf("nodeName = %v, want n1", got)
			}
		}},
		{"Put stores a copy, as the wire would carry it", func(t *testing.T, s *kubetest.Server) {
			obj := map[string]any{"spec": map[string]any{"n": 1, "list": []string{"x"}}}
			s.Put(podPath, obj)
			obj["spec"].(map[string]any)["n"] = 2
			if got := at(s.Get(podPath), "spec"); !reflect.DeepEqual(got, map[string]any{"n": 1.0, "list": []any{"x"}}) {
				t.Fatalf("spec = %v", got)
			}
		}},
		{"Put keeps a given name and uid", func(t *testing.T, s *kubetest.Server) {
			s.Put(podPath, map[string]any{"metadata": map[string]any{"name": "given", "uid": "u"}})
			if got := at(s.Get(podPath), "metadata"); !reflect.DeepEqual(got, map[string]any{"name": "given", "uid": "u", "namespace": "ns"}) {
				t.Fatalf("metadata = %v", got)
			}
		}},
		{"Put of an object that does not marshal panics", func(t *testing.T, s *kubetest.Server) {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(r.(string), "does not marshal") {
					t.Fatalf("recovered %v, want the marshal panic", r)
				}
			}()
			s.Put(podPath, map[string]any{"bad": make(chan int)})
		}},
		{"Update changes the stored object and reports it existed", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			if !s.Update(podPath, func(o map[string]any) { o["spec"].(map[string]any)["nodeName"] = "n9" }) {
				t.Fatal("Update reported a seeded object missing")
			}
			if got := at(s.Get(podPath), "spec", "nodeName"); got != "n9" {
				t.Fatalf("nodeName = %v, want n9", got)
			}
		}},
		{"Update of a missing object reports false and calls nothing", func(t *testing.T, s *kubetest.Server) {
			if s.Update(podPath, func(map[string]any) { t.Fatal("called for a missing object") }) {
				t.Fatal("Update reported a missing object present")
			}
		}},
		{"Delete takes the object; a missing one is no error", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			s.Delete(podPath)
			s.Delete(podPath)
			if s.Get(podPath) != nil {
				t.Fatal("deleted object still stored")
			}
		}},
		{"Fail with a count fails that many requests, then serves", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			s.Fail("GET", podPath, 503, 2)
			for i, want := range []int{503, 503, 200} {
				code, resp := send(t, s, "GET", podPath, "", "")
				if code != want {
					t.Fatalf("request %d = %d, want %d", i, code, want)
				}
				if code == 503 && (resp["reason"] != "Injected" || resp["code"] != 503.0) {
					t.Fatalf("injected answer = %v", resp)
				}
			}
		}},
		{"Fail without a count fails every request until cleared", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			s.Fail("GET", podPath, 500, 0)
			for range 3 {
				if code, _ := send(t, s, "GET", podPath, "", ""); code != 500 {
					t.Fatalf("GET = %d, want 500", code)
				}
			}
			if code, _ := send(t, s, "DELETE", podPath, "", ""); code != 200 {
				t.Fatalf("another verb on the path = %d, want it served", code)
			}
			s.Fail("GET", podPath, 0, 0)
			if code, _ := send(t, s, "GET", podPath, "", ""); code != 404 {
				t.Fatalf("GET after clearing = %d, want the real answer 404", code)
			}
		}},
		{"Calls records each request as the client sent it", func(t *testing.T, s *kubetest.Server) {
			seedPod(s)
			send(t, s, "GET", podPath+"/", "", "")
			send(t, s, "PATCH", podPath, "application/merge-patch+json", `{"a":1}`)
			want := []kubetest.Call{
				{Method: "GET", Path: podPath, Authorization: "Bearer tok"},
				{Method: "PATCH", Path: podPath, ContentType: "application/merge-patch+json", Authorization: "Bearer tok", Body: `{"a":1}`},
			}
			if got := s.Calls(); !reflect.DeepEqual(got, want) {
				t.Fatalf("calls = %+v, want %+v", got, want)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New()
			t.Cleanup(s.Close)
			tc.run(t, s)
		})
	}
}
