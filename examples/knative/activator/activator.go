// Package activator is Knative's scale-from-zero, done with fibers. In
// Knative Serving the activator fronts a revision that has no Pods: it
// holds the request, asks the autoscaler for a Pod, and proxies once one
// is ready, in seconds. Here a revision is a session on a fiberd home
// whose backend is a Hyperlight sandbox: the first request Clones it
// (milliseconds from the warm snapshot), later requests attach, an idle
// revision is parked (its state kept, its memory freed), and the next
// request resumes it. The activator is a consumer: it holds the
// revision's grant and speaks only Clone, Park and Release.
//
// Misses are Knative's own fallbacks: DEFERRED_FALLBACK is "scale a Pod
// the ordinary way" (reported to the caller here as 503 with the home
// the session lives on, since this example has no Pods); SHED is
// "control plane unreachable, retry later" (503 with Retry-After).
package activator

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/endpoint"
)

// Revision is one function: a grant on a home and a session name.
type Revision struct {
	Name string
	// Grant is the signed grant the activator holds for this revision.
	Grant string
	// Concurrency is how many fibers serve the revision at once (each is
	// a session "<name>-<i>"); default 1.
	Concurrency int
	// Mode is how requests reach the fiber: "http" proxies the HTTP
	// request to the endpoint (a guest that serves HTTP); "line" sends
	// the request body as one line of the reference guest's protocol and
	// returns the reply (what the reference guests speak).
	Mode string
}

type Config struct {
	Revisions []Revision
	// Idle: a fiber unused for this long is parked (0 = never).
	Idle time.Duration
	// CloneDeadline is the runtime budget per Clone.
	CloneDeadline time.Duration
	// Dial reaches a fiber endpoint; nil means endpoint.Dial.
	Dial func(ctx context.Context, ep string) (net.Conn, error)
}

type slot struct {
	session string
	mu      sync.Mutex
	fiber   *consumer.Fiber
	lastUse time.Time
	inUse   int
}

type revision struct {
	Revision
	slots []*slot
}

type Activator struct {
	cfg    Config
	client *consumer.Client
	revs   map[string]*revision
	mu     sync.Mutex
}

func New(client *consumer.Client, cfg Config) (*Activator, error) {
	if cfg.CloneDeadline <= 0 {
		cfg.CloneDeadline = 5 * time.Second
	}
	if cfg.Dial == nil {
		cfg.Dial = endpoint.Dial
	}
	a := &Activator{cfg: cfg, client: client, revs: map[string]*revision{}}
	for _, r := range cfg.Revisions {
		if r.Name == "" || r.Grant == "" {
			return nil, errors.New("activator: a revision needs a name and a grant")
		}
		if r.Concurrency <= 0 {
			r.Concurrency = 1
		}
		if r.Mode == "" {
			r.Mode = "line"
		}
		rv := &revision{Revision: r}
		for i := 0; i < r.Concurrency; i++ {
			rv.slots = append(rv.slots, &slot{session: fmt.Sprintf("%s-%d", r.Name, i)})
		}
		a.revs[r.Name] = rv
	}
	if len(a.revs) == 0 {
		return nil, errors.New("activator: no revisions")
	}
	return a, nil
}

// Run parks idle fibers until ctx ends.
func (a *Activator) Run(ctx context.Context) {
	if a.cfg.Idle <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(a.cfg.Idle / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.parkIdle(ctx, now)
		}
	}
}

func (a *Activator) parkIdle(ctx context.Context, now time.Time) {
	for _, rv := range a.revs {
		for _, s := range rv.slots {
			s.mu.Lock()
			if s.fiber != nil && s.inUse == 0 && now.Sub(s.lastUse) >= a.cfg.Idle {
				f := s.fiber
				// A park is the backend's checkpoint (a Hyperlight snapshot
				// is hundreds of milliseconds); a hang here must be seen,
				// not silently hold the slot.
				pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				err := a.client.Park(pctx, f.ID, false)
				cancel()
				if err != nil && !consumer.NotFound(err) {
					log.Printf("activator: park %s (%s): %v", s.session, f.ID, err)
				} else {
					log.Printf("activator: parked %s (%s) after %s idle", s.session, f.Fence, a.cfg.Idle)
					s.fiber = nil
				}
			}
			s.mu.Unlock()
		}
	}
}

// route picks the revision: the first path segment, else the Host's
// first label, else the only revision.
func (a *Activator) route(r *http.Request) (*revision, string) {
	if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" {
		name, rest, _ := strings.Cut(p, "/")
		if rv, ok := a.revs[name]; ok {
			return rv, "/" + rest
		}
	}
	if host, _, err := net.SplitHostPort(r.Host); err == nil || r.Host != "" {
		if host == "" {
			host = r.Host
		}
		if rv, ok := a.revs[strings.Split(host, ".")[0]]; ok {
			return rv, r.URL.Path
		}
	}
	if len(a.revs) == 1 {
		for _, rv := range a.revs {
			return rv, r.URL.Path
		}
	}
	return nil, ""
}

// pick chooses the slot for a request: the least busy slot that already
// serves a fiber, unless every serving slot is busy and an empty one is
// free, in which case the empty one (a second fiber is cloned only when
// the first cannot take the request).
func (a *Activator) pick(rv *revision) *slot {
	a.mu.Lock()
	defer a.mu.Unlock()
	var serving, empty *slot
	for _, s := range rv.slots {
		s.mu.Lock()
		switch {
		case s.fiber != nil && (serving == nil || s.inUse < serving.inUse):
			serving = s
		case s.fiber == nil && empty == nil:
			empty = s
		}
		s.mu.Unlock()
	}
	switch {
	case serving == nil:
		return empty
	case serving.inUse > 0 && empty != nil:
		return empty
	default:
		return serving
	}
}

// acquire returns a serving fiber for the revision, cloning (or
// resuming) one when the chosen slot has none. A request served by a
// fiber the activator already holds is an attach.
func (a *Activator) acquire(ctx context.Context, rv *revision) (*slot, consumer.Fiber, error) {
	s := a.pick(rv)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fiber == nil {
		f, err := a.client.Clone(ctx, rv.Grant, s.session, a.cfg.CloneDeadline, nil)
		if err != nil {
			return nil, consumer.Fiber{}, err
		}
		log.Printf("activator: %s %s -> %s (%s)", f.Kind, s.session, f.Endpoint, f.Fence)
		s.fiber = &f
		s.inUse++
		s.lastUse = time.Now()
		return s, f, nil
	}
	s.inUse++
	s.lastUse = time.Now()
	f := *s.fiber
	f.Kind = Attach
	return s, f, nil
}

// Attach marks a request served by a fiber the activator already held.
const Attach = consumer.Attach

func (a *Activator) release(s *slot, gone bool) {
	s.mu.Lock()
	s.inUse--
	s.lastUse = time.Now()
	if gone {
		s.fiber = nil
	}
	s.mu.Unlock()
}

// ServeHTTP is the activator's data path.
func (a *Activator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rv, path := a.route(r)
	if rv == nil {
		http.Error(w, "no such revision", http.StatusNotFound)
		return
	}
	s, f, err := a.acquire(r.Context(), rv)
	if err != nil {
		a.miss(w, err)
		return
	}
	w.Header().Set("X-Fiberd-Clone", f.Kind.String())
	w.Header().Set("X-Fiberd-Fence", f.Fence.String())
	w.Header().Set("X-Fiberd-Session", s.session)
	switch rv.Mode {
	case "http":
		gone := a.proxyHTTP(w, r, f, path)
		a.release(s, gone)
	default:
		gone := a.proxyLine(w, r, f)
		a.release(s, gone)
	}
}

// miss maps the consumer's typed errors to what a caller in front of
// Knative expects.
func (a *Activator) miss(w http.ResponseWriter, err error) {
	var shed *consumer.Shed
	var def *consumer.Deferred
	var gap *consumer.TierGap
	switch {
	case errors.As(err, &shed):
		w.Header().Set("Retry-After", strconv.Itoa(int(shed.RetryAfter/time.Second)))
		http.Error(w, "shed: "+err.Error(), http.StatusServiceUnavailable)
	case errors.As(err, &def):
		if def.PreferredHome != "" {
			w.Header().Set("X-Fiberd-Preferred-Home", def.PreferredHome)
		}
		http.Error(w, "deferred: take the ordinary path: "+def.Reason, http.StatusServiceUnavailable)
	case errors.As(err, &gap):
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
	default:
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

// proxyLine: the request body (first line) goes to the fiber as one
// protocol line, the reply comes back as the response body. GET with no
// body pings. Reports whether the fiber turned out to be gone.
func (a *Activator) proxyLine(w http.ResponseWriter, r *http.Request, f consumer.Fiber) bool {
	line := "ping"
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if s := strings.TrimSpace(string(b)); s != "" {
			line, _, _ = strings.Cut(s, "\n")
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	c, err := a.cfg.Dial(ctx, f.Endpoint)
	if err != nil {
		http.Error(w, "fiber unreachable: "+err.Error(), http.StatusBadGateway)
		return true
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		http.Error(w, "fiber write: "+err.Error(), http.StatusBadGateway)
		return true
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && reply == "" {
		http.Error(w, "fiber reply: "+err.Error(), http.StatusBadGateway)
		return true
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, strings.TrimRight(reply, "\n")+"\n")
	return false
}

// proxyHTTP forwards the request to a guest that serves HTTP on its
// endpoint.
func (a *Activator) proxyHTTP(w http.ResponseWriter, r *http.Request, f consumer.Fiber, path string) bool {
	gone := false
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "fiber"
			pr.Out.URL.Path = path
			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}
			pr.Out.Host = r.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return a.cfg.Dial(ctx, f.Endpoint) },
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			gone = true
			http.Error(w, "fiber: "+err.Error(), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	return gone
}
