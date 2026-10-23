//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
)

// GPU is what C14 needs besides the peer, whose engine names another
// GPU than the target's.
type GPU struct {
	// Class is the device class of C14's grants. sim for the reference
	// engine's simulated pool, gpu on hardware.
	Class string
	// Layout is a third home sharing the registry and keys, whose engine
	// declares another layout than the target's and the peer's.
	Layout *Peer
	// Layouts are the two layouts the third home's refusal must name,
	// the session's and its own.
	Layouts [2]string
	// Events is where C14 writes one NDJSON line per step. Empty writes
	// none.
	Events string
	// VM is the events' vm field, where the homes run.
	VM string
	// Backend is the events' backend field, the target's runtime.
	Backend string
	// Name is the GPU the target's engine declares, the third home's too.
	Name string
	// PeerName is the GPU the peer's engine declares.
	PeerName string
	// Volatile says the backend's restore restarts the guest (the fake
	// VMM), so the hash gpufill kept is gone after a resume. C14 then
	// asks the engine for the slice's hash under the new fence itself,
	// a weaker check than gpucheck.
	Volatile bool
}

const (
	// gpuFill is the slice C14 fills, 4 MiB.
	gpuFill = 4 << 20
	// gpuBudget is the device budget of C14's grants, room for the fill.
	gpuBudget = 8 << 20
	// gpuSeed seeds the fill.
	gpuSeed = 14
	// gpuRetries bounds the clones C14 sends again while a home answers
	// Unavailable, a miss its engine coming up may cause.
	gpuRetries = 20
)

// gpuNodes are the GPU nodes, major 195, the fiber must fail to open.
var gpuNodes = []string{"/dev/nvidiactl", "/dev/nvidia0"}

// gpuEvent is one line of C14's stream, its fields in the reader's
// order. The reader refuses any other top-level field.
type gpuEvent struct {
	Seq     int            `json:"seq"`
	TMS     int64          `json:"t_ms"`
	VM      string         `json:"vm"`
	Home    string         `json:"home"`
	Backend string         `json:"backend"`
	GPU     string         `json:"gpu"`
	Kind    string         `json:"kind"`
	Fiber   string         `json:"fiber"`
	Data    map[string]any `json:"data"`
}

// gpuStream writes C14's stream. seq rises from 1, and t_ms counts from
// C14's start on the monotonic clock, so it never goes back. Without a
// file it writes nothing. No line carries a token.
type gpuStream struct {
	f   *os.File
	g   *GPU
	t0  time.Time
	seq int
}

func newGPUStream(g *GPU) (*gpuStream, error) {
	e := &gpuStream{g: g, t0: time.Now()}
	if g.Events == "" {
		return e, nil
	}
	f, err := os.OpenFile(g.Events, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("-gpu-events: %w", err)
	}
	e.f = f
	return e, nil
}

func (e *gpuStream) close() {
	if e.f != nil {
		_ = e.f.Close()
	}
}

// emit writes one line for a step of scene on home h. A write that fails
// is logged, since the stream records the run and is not one of its
// checks.
func (e *gpuStream) emit(t *testing.T, h *gpuHome, kind, fiber string, scene int, data map[string]any) {
	t.Helper()
	if e.f == nil {
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["scene"] = scene
	e.seq++
	b, err := json.Marshal(gpuEvent{Seq: e.seq, TMS: time.Since(e.t0).Milliseconds(), VM: e.g.VM, Home: h.node,
		Backend: e.g.Backend, GPU: h.gpu, Kind: kind, Fiber: fiber, Data: data})
	if err == nil {
		_, err = e.f.Write(append(b, '\n'))
	}
	if err != nil {
		t.Logf("C14 events: %v", err)
	}
}

// fail writes the failed line and ends C14 with the same words.
func (e *gpuStream) fail(t *testing.T, h *gpuHome, fiber string, scene int, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	e.emit(t, h, "failed", fiber, scene, map[string]any{"answer": msg})
	t.Fatal(msg)
}

// since is the milliseconds from t0, an event's ms.
func since(t0 time.Time) int64 { return time.Since(t0).Milliseconds() }

// gpuHome is one home C14 drives, with the grant minted for it.
type gpuHome struct {
	api  grantv1.FibersClient
	node string
	gpu  string
	tok  string
}

// dial is a Fibers client for another home, closed when t ends.
func (c *client) dial(t *testing.T, target string) grantv1.FibersClient {
	t.Helper()
	creds := insecure.NewCredentials()
	if c.d.TLS != nil {
		creds = credentials.NewTLS(c.d.TLS)
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return grantv1.NewFibersClient(conn)
}

// clone asks h for the session. An Unavailable answer is asked again a
// few times, since a grant's engine that is not up yet is such a miss.
func (h *gpuHome) clone(ctx context.Context, session string) (*grantv1.CloneResponse, error) {
	var r *grantv1.CloneResponse
	var err error
	for range gpuRetries {
		r, err = h.api.Clone(ctx, &grantv1.CloneRequest{GrantJwt: h.tok, Session: session})
		if status.Code(err) != codes.Unavailable {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, err
		case <-time.After(250 * time.Millisecond):
		}
	}
	return r, err
}

func (h *gpuHome) release(ctx context.Context, id string) {
	_, _ = h.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: id, Discard: true})
}

// ask sends one line of the fiber line protocol to the fiber at ep and
// gives its one-line reply. Every backend's fibers speak it, Hyperlight's
// included, which serve no HTTP.
func ask(ctx context.Context, ep, line string) (string, error) {
	conn, err := endpoint.Dial(ctx, ep)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := io.WriteString(conn, line+"\n"); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("%s: %w", line, err)
	}
	return strings.TrimRight(reply, "\r\n"), nil
}

// C14: the answer check. A fiber on the target fills a device slice and
// fails to open any GPU node. Parked and published, the session resumes
// on the peer, whose engine names another GPU, and the slice hashes as
// it did. Parked again, a third home whose engine declares another
// layout refuses it before the claim, naming both layouts, so the
// session stays in the registry and resumes on the peer once more. It
// runs on whatever backend the homes run, through the fiber line
// protocol.
func (c *client) c14(t *testing.T) {
	g := c.d.GPU
	if g == nil {
		t.Skip("no -gpu; the GPU answer check not driven")
	}
	if c.d.Peer == nil || g.Layout == nil {
		t.Fatal("C14 needs the peer and the third home")
	}
	if c.d.TargetTier < core.TierCheckpoint {
		t.Skipf("target tier %s is below FIBER_CHECKPOINT; no park to move", c.d.TargetTier)
	}
	ev, err := newGPUStream(g)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.close()
	ctx, cancel := c.ctx(t, 6)
	defer cancel()
	budget := func(aud string) func(*core.Grant) {
		return func(gr *core.Grant) {
			gr.DeviceBudget = core.DeviceBudget{Bytes: gpuBudget, Class: g.Class}
			gr.Audience = aud
		}
	}
	// One grant per home, the same tenant and template, so the session
	// moves within its domain.
	_, tokA := c.grant(t, "c14a", budget(c.d.NodeID))
	_, tokB := c.grant(t, "c14b", budget(c.d.Peer.NodeID))
	_, tokC := c.grant(t, "c14c", budget(g.Layout.NodeID))
	a := &gpuHome{api: c.api, node: c.d.NodeID, gpu: g.Name, tok: tokA}
	b := &gpuHome{api: c.dial(t, c.d.Peer.Target), node: c.d.Peer.NodeID, gpu: g.PeerName, tok: tokB}
	l := &gpuHome{api: c.dial(t, g.Layout.Target), node: g.Layout.NodeID, gpu: g.Name, tok: tokC}
	session := uid("G")
	// C14 compares no GPU names. Two MIG instances of one GPU declare the
	// same name, so equal names on real GPUs are logged, as the move test
	// logs them.
	if g.Name == g.PeerName && g.Class == "gpu" {
		t.Logf("C14: the target's and the peer's GPU are both %s, as two MIG instances of one GPU report", g.Name)
	} else {
		t.Logf("C14: the target's GPU is %s, the peer's %s, class %s", g.Name, g.PeerName, g.Class)
	}
	ev.emit(t, a, "facts", "", 1, nil)

	// Scene 1. The clone, the fill, and the GPU nodes it cannot open.
	t0 := time.Now()
	r1, err := a.clone(ctx, session)
	if err != nil {
		ev.fail(t, a, "", 1, "clone on the target: %v", err)
	}
	id := r1.GetFiberId()
	defer a.release(ctx, id)
	if r1.GetKind() != grantv1.CloneKind_CREATE {
		ev.fail(t, a, id, 1, "first clone kind = %v, want CREATE", r1.GetKind())
	}
	ev.emit(t, a, "clone", id, 1, map[string]any{"ms": since(t0), "answer": r1.GetKind().String()})
	t0 = time.Now()
	filled, err := ask(ctx, r1.GetEndpoint(), fmt.Sprintf("gpufill %d %d", gpuSeed, gpuFill))
	if err != nil || !strings.HasPrefix(filled, "ok ") {
		ev.fail(t, a, id, 1, "gpufill of %d bytes = %q, %v, want ok <hash>", gpuFill, filled, err)
	}
	ev.emit(t, a, "fill", id, 1, map[string]any{"ms": since(t0), "answer": filled})
	for _, node := range gpuNodes {
		got, err := ask(ctx, r1.GetEndpoint(), "gpuopen "+node)
		switch {
		case err != nil:
			ev.fail(t, a, id, 1, "gpuopen %s: %v", node, err)
		case got == "ok":
			ev.fail(t, a, id, 1, "the fiber opened %s, a GPU node", node)
		case got == "" || strings.HasPrefix(got, "err "):
			ev.fail(t, a, id, 1, "gpuopen %s = %q, want an errno name", node, got)
		}
		t.Logf("gpuopen %s: %s", node, got)
		ev.emit(t, a, "device", id, 1, map[string]any{"devices": []string{}, "errno": got, "answer": "gpuopen " + node + ": " + got})
	}

	// Scene 2. The park saves the slice and publishes the session.
	t0 = time.Now()
	if _, err := a.api.Park(ctx, &grantv1.ParkRequest{FiberId: id, Sync: true}); err != nil {
		ev.fail(t, a, id, 2, "park on the target: %v", err)
	}
	ev.emit(t, a, "save", id, 2, map[string]any{"ms": since(t0), "answer": "parked, the slice saved"})
	ev.emit(t, a, "publish", "", 2, map[string]any{"answer": "session " + session + " published"})

	// Scene 3. The peer claims it, resumes it, and the slice is the same.
	t0 = time.Now()
	r2, err := b.clone(ctx, session)
	if err != nil {
		ev.fail(t, b, "", 3, "clone on the peer: %v", err)
	}
	id = r2.GetFiberId()
	defer b.release(ctx, id)
	if r2.GetKind() != grantv1.CloneKind_RESUME {
		ev.fail(t, b, id, 3, "clone on the peer kind = %v, want RESUME of the session parked on the target", r2.GetKind())
	}
	ev.emit(t, b, "claim", "", 3, map[string]any{"ms": since(t0), "answer": "claimed from " + a.node})
	ev.emit(t, b, "resume", id, 3, map[string]any{"answer": r2.GetKind().String()})
	t0 = time.Now()
	if g.Volatile {
		c.c14Volatile(ctx, t, ev, b, id, r2.GetEndpoint(), filled, t0)
	} else {
		checked, err := ask(ctx, r2.GetEndpoint(), "gpucheck")
		if err != nil {
			ev.fail(t, b, id, 3, "gpucheck on the peer: %v", err)
		}
		ev.emit(t, b, "check", id, 3, map[string]any{"ms": since(t0), "answer": checked})
		if checked != "ok" {
			ev.fail(t, b, id, 3, "gpucheck on the peer = %q, want ok: the slice did not survive the move", checked)
		}
	}

	// Scene 4. Parked again, the session is refused by an engine of
	// another layout, before the claim, and stays for the peer.
	t0 = time.Now()
	if _, err := b.api.Park(ctx, &grantv1.ParkRequest{FiberId: id, Sync: true}); err != nil {
		ev.fail(t, b, id, 4, "park on the peer: %v", err)
	}
	ev.emit(t, b, "save", id, 4, map[string]any{"ms": since(t0), "answer": "parked, the slice saved"})
	ev.emit(t, b, "publish", "", 4, map[string]any{"answer": "session " + session + " published"})
	t0 = time.Now()
	r3, err := l.clone(ctx, session)
	if err == nil {
		l.release(ctx, r3.GetFiberId())
		ev.fail(t, l, r3.GetFiberId(), 4, "the home of another layout took the session, kind %v, want FailedPrecondition", r3.GetKind())
	}
	msg := status.Convert(err).Message()
	if status.Code(err) != codes.FailedPrecondition {
		ev.fail(t, l, "", 4, "clone on the home of another layout: code %v, want FailedPrecondition (err: %v)", status.Code(err), err)
	}
	for _, name := range g.Layouts {
		if !strings.Contains(msg, name) {
			ev.fail(t, l, "", 4, "the refusal %q does not name layout %s", msg, name)
		}
	}
	ev.emit(t, l, "refuse", "", 4, map[string]any{"ms": since(t0), "answer": msg})
	t0 = time.Now()
	r4, err := b.clone(ctx, session)
	if err != nil {
		ev.fail(t, b, "", 4, "clone on the peer after the refusal: %v", err)
	}
	defer b.release(ctx, r4.GetFiberId())
	if r4.GetKind() != grantv1.CloneKind_RESUME {
		ev.fail(t, b, r4.GetFiberId(), 4, "clone on the peer after the refusal kind = %v, want RESUME: the session left the registry", r4.GetKind())
	}
	ev.emit(t, b, "resume", r4.GetFiberId(), 4, map[string]any{"ms": since(t0), "answer": r4.GetKind().String()})
}

// c14Volatile is scene 3's check on a backend whose restore restarts the
// guest, which loses the hash gpufill kept. The resumed fiber names its
// fence, which must be the Clone reply's fiber id, and the engine's hash
// of the slice under that fence, asked through the fiber, must be the
// one gpufill returned.
func (c *client) c14Volatile(ctx context.Context, t *testing.T, ev *gpuStream, b *gpuHome, id, ep, filled string, t0 time.Time) {
	t.Helper()
	t.Logf("C14 on %s: its restore restarts the guest, so the weaker check runs, engine sum under the new fence against gpufill's hash", c.d.GPU.Backend)
	fence, err := ask(ctx, ep, "fence")
	if err != nil {
		ev.fail(t, b, id, 3, "fence on the peer: %v", err)
	}
	if fence != id {
		ev.fail(t, b, id, 3, "the resumed fiber names fence %q, want %q, the Clone reply's", fence, id)
	}
	summed, err := ask(ctx, ep, "engine sum "+fence)
	if err != nil {
		ev.fail(t, b, id, 3, "engine sum on the peer: %v", err)
	}
	ev.emit(t, b, "check", id, 3, map[string]any{"ms": since(t0), "answer": summed, "volatile": true})
	if summed != filled {
		ev.fail(t, b, id, 3, "engine sum %s on the peer = %q, want %q from gpufill: the slice did not survive the move", fence, summed, filled)
	}
}
