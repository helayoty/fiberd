// Package kubetest is an in-memory stand-in for the API server, enough
// for the controller and the home to be tested without a cluster: objects
// keyed by path, collections listed by prefix, merge patches applied,
// uids assigned on create, owner references garbage-collected on delete.
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
	// Requests records method + path in order.
	Requests []string
}

func New() *Server {
	s := &Server{objects: map[string]map[string]any{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string { return s.srv.URL }
func (s *Server) Close()      { s.srv.Close() }

// Put stores an object at path (a test's seed); the uid is assigned if
// missing.
func (s *Server) Put(path string, obj map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store(path, obj)
}

// Get returns a stored object, or nil.
func (s *Server) Get(path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[path]
}

// Delete removes an object the way the API server would, with its
// dependents.
func (s *Server) Delete(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remove(path)
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
	uid, _ := obj["metadata"].(map[string]any)["uid"].(string)
	delete(s.objects, path)
	for p, o := range s.objects {
		refs, _ := o["metadata"].(map[string]any)["ownerReferences"].([]any)
		for _, r := range refs {
			if rm, _ := r.(map[string]any); rm != nil && rm["uid"] == uid {
				s.remove(p)
				break
			}
		}
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimSuffix(r.URL.Path, "/")
	s.Requests = append(s.Requests, r.Method+" "+path)
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		if obj, ok := s.objects[path]; ok {
			_ = json.NewEncoder(w).Encode(obj)
			return
		}
		// A collection: everything one level (or, for a cluster-wide list
		// of a namespaced resource, "namespaces/<ns>/<resource>/<name>")
		// below the path.
		items := []map[string]any{}
		keys := make([]string, 0, len(s.objects))
		for p := range s.objects {
			keys = append(keys, p)
		}
		sort.Strings(keys)
		if !isCollection(path) {
			notFound(w, path)
			return
		}
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
		name, _ := obj["metadata"].(map[string]any)["name"].(string)
		if name == "" {
			http.Error(w, `{"message":"metadata.name required"}`, http.StatusUnprocessableEntity)
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
			patch = map[string]any{"status": patch["status"]}
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
