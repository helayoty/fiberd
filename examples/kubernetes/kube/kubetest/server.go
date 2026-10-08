// Package kubetest is an in-memory stand-in for the API server, enough
// for the controller and the home to be tested without a cluster: objects
// keyed by path, collections listed by prefix, merge patches applied,
// uids assigned on create, owner references garbage-collected on delete.
// Every request is recorded, and a test can make chosen requests fail.
package kubetest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
)

type Server struct {
	mu      sync.Mutex
	objects map[string]map[string]any // object path -> object
	next    int
	srv     *httptest.Server
	calls   []Call
	faults  map[string]*fault // "METHOD path" -> fault
}

// Call is one request the server received, as the client sent it.
type Call struct {
	Method, Path string
	// ContentType and Authorization are the request's headers.
	ContentType, Authorization string
	Body                       string
}

type fault struct {
	code  int
	times int // requests left to fail; 0 or less fails every one
}

func New() *Server {
	s := &Server{objects: map[string]map[string]any{}, faults: map[string]*fault{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string { return s.srv.URL }
func (s *Server) Close()      { s.srv.Close() }

// Put stores a copy of obj at path (a test's seed); the uid is assigned
// if missing. The copy is what the wire would carry, so typed slices and
// maps read back as JSON values.
func (s *Server) Put(path string, obj map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store(path, clone(obj))
}

// Get returns a copy of a stored object, or nil.
func (s *Server) Get(path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obj, ok := s.objects[path]; ok {
		return clone(obj)
	}
	return nil
}

// Update changes a stored object in place, the way another client of the
// API server would. It reports whether the object exists.
func (s *Server) Update(path string, fn func(obj map[string]any)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[path]
	if ok {
		fn(obj)
	}
	return ok
}

// Delete removes an object the way the API server would, with its
// dependents.
func (s *Server) Delete(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remove(path)
}

// Calls is every request received so far, in order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Fail makes requests with method and path answer code with a Status
// body instead of being served. times is how many requests fail, and 0
// or less means every one. A code of 0 removes the fault.
func (s *Server) Fail(method, path string, code, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := method + " " + path
	if code == 0 {
		delete(s.faults, key)
		return
	}
	s.faults[key] = &fault{code: code, times: times}
}

// clone is a deep copy of obj through JSON.
func clone(obj map[string]any) map[string]any {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(fmt.Sprintf("kubetest: object does not marshal: %v", err))
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || out == nil {
		out = map[string]any{}
	}
	return out
}

func (s *Server) store(path string, obj map[string]any) {
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	if _, ok := meta["uid"]; !ok {
		s.next++
		meta["uid"] = fmt.Sprintf("uid-%d", s.next)
	}
	if name, ok := meta["name"].(string); ok && name == "" || !ok {
		meta["name"] = path[strings.LastIndex(path, "/")+1:]
	}
	if segs := strings.Split(path, "/"); len(segs) > 4 && segs[len(segs)-4] == "namespaces" {
		meta["namespace"] = segs[len(segs)-3]
	}
	s.objects[path] = obj
}

func (s *Server) remove(path string) {
	obj, ok := s.objects[path]
	if !ok {
		return
	}
	meta, _ := obj["metadata"].(map[string]any)
	uid, _ := meta["uid"].(string)
	delete(s.objects, path)
	for p, o := range s.objects {
		meta, _ := o["metadata"].(map[string]any)
		refs, _ := meta["ownerReferences"].([]any)
		for _, r := range refs {
			if rm, _ := r.(map[string]any); rm != nil && rm["uid"] == uid {
				s.remove(p)
				break
			}
		}
	}
}

// failed answers the request from a fault set for it, if any.
func (s *Server) failed(w http.ResponseWriter, method, path string) bool {
	key := method + " " + path
	f, ok := s.faults[key]
	if !ok {
		return false
	}
	if f.times > 0 {
		if f.times--; f.times == 0 {
			delete(s.faults, key)
		}
	}
	w.WriteHeader(f.code)
	_, _ = fmt.Fprintf(w, `{"kind":"Status","reason":"Injected","message":"injected %d for %s","code":%d}`, f.code, key, f.code)
	return true
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimSuffix(r.URL.Path, "/")
	body, _ := io.ReadAll(r.Body)
	s.calls = append(s.calls, Call{Method: r.Method, Path: path, ContentType: r.Header.Get("Content-Type"),
		Authorization: r.Header.Get("Authorization"), Body: string(body)})
	w.Header().Set("Content-Type", "application/json")
	if s.failed(w, r.Method, path) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if obj, ok := s.objects[path]; ok {
			_ = json.NewEncoder(w).Encode(obj)
			return
		}
		// A collection: everything one level (or, for a cluster-wide list
		// of a namespaced resource, "namespaces/<ns>/<resource>/<name>")
		// below the path.
		if !isCollection(path) {
			notFound(w, path)
			return
		}
		keys := make([]string, 0, len(s.objects))
		for p := range s.objects {
			keys = append(keys, p)
		}
		sort.Strings(keys)
		items := []map[string]any{}
		resource := path[strings.LastIndex(path, "/")+1:]
		base := path[:strings.LastIndex(path, "/")] // group/version root for a cluster-wide list
		for _, p := range keys {
			if rest := strings.TrimPrefix(p, path+"/"); rest != p && !strings.Contains(rest, "/") {
				items = append(items, s.objects[p]) // namespaced list
				continue
			}
			if rest := strings.TrimPrefix(p, base+"/namespaces/"); rest != p {
				if segs := strings.Split(rest, "/"); len(segs) == 3 && segs[1] == resource {
					items = append(items, s.objects[p]) // cluster-wide list of a namespaced resource
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	case http.MethodPost:
		var obj map[string]any
		if err := json.Unmarshal(body, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		if name == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"Invalid","message":"metadata.name required","code":422}`))
			return
		}
		p := path + "/" + name
		if _, exists := s.objects[p]; exists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"AlreadyExists","message":"already exists","code":409}`))
			return
		}
		s.store(p, obj)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodPatch:
		target := strings.TrimSuffix(path, "/status")
		obj, ok := s.objects[target]
		if !ok {
			notFound(w, target)
			return
		}
		var patch map[string]any
		if err := json.Unmarshal(body, &patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(path, "/status") {
			// The status subresource changes the status and nothing else.
			st, ok := patch["status"]
			patch = map[string]any{}
			if ok {
				patch["status"] = st
			}
		}
		merge(obj, patch, r.Header.Get("Content-Type") == "application/strategic-merge-patch+json")
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodDelete:
		if _, ok := s.objects[path]; !ok {
			notFound(w, path)
			return
		}
		s.remove(path)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

// isCollection: /api/v1/<res>, /api/v1/namespaces/<ns>/<res>, and the
// /apis/<group>/<version> forms of both. One segment more is an object.
func isCollection(path string) bool {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch segs[0] {
	case "api":
		return len(segs) == 3 || (len(segs) == 5 && segs[2] == "namespaces")
	case "apis":
		return len(segs) == 4 || (len(segs) == 6 && segs[3] == "namespaces")
	}
	return false
}

func notFound(w http.ResponseWriter, path string) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(w, `{"kind":"Status","reason":"NotFound","message":"%s not found","code":404}`, path)
}

// merge applies an RFC 7386 merge patch; with strategic set, a list of
// objects keyed by "type" (Pod conditions) or "name" is merged by key.
func merge(dst, patch map[string]any, strategic bool) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(map[string]any)
		if pok && dok {
			merge(dm, pm, strategic)
			continue
		}
		if pl, ok := v.([]any); ok && strategic {
			if dl, ok := dst[k].([]any); ok {
				dst[k] = mergeList(dl, pl)
				continue
			}
		}
		dst[k] = v
	}
}

func mergeList(dst, patch []any) []any {
	key := func(m map[string]any) string {
		for _, k := range []string{"type", "name"} {
			if s, ok := m[k].(string); ok {
				return k + "=" + s
			}
		}
		return ""
	}
	out := append([]any(nil), dst...)
	for _, p := range patch {
		pm, _ := p.(map[string]any)
		replaced := false
		if pm != nil {
			if pk := key(pm); pk != "" {
				for i, d := range out {
					if dm, _ := d.(map[string]any); dm != nil && key(dm) == pk {
						out[i] = p
						replaced = true
						break
					}
				}
			}
		}
		if !replaced {
			out = append(out, p)
		}
	}
	return out
}
