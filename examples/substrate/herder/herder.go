// Package herder is an Agent Substrate sandbox-class herder (what
// Substrate calls an "ateom") whose actors are fibers. Substrate's node
// supervisor, atelet, drives every worker Pod's herder over one gRPC
// service: run an actor, checkpoint it to files, restore it from files,
// terminate it, sample its usage. This herder answers those calls with
// fiberd's four verbs on the agent running beside it in the same Pod:
//
//	RunWorkload         Clone(actor uid)               a fresh session, kind CREATE
//	CheckpointWorkload  Park(sync) + host.ExportDelta   the session leaves as files
//	RestoreWorkload     host.ImportDelta + Clone(uid)   the files come back, kind RESUME
//	TerminateWorkload   Release(discard)
//	stats               Watch                           W of the actor's grant
//
// An actor is a session named by its uid; an ActorTemplate is a fiberd
// template (digest "<atespace>/<name>", resolved through the agent's
// -template map) under a grant this Pod mints for itself, sized by the
// actor's memory limit. One actor per worker, as Substrate's Worker
// record assumes today. The herder is a consumer: it holds grants and
// speaks only Clone, Park, Release and Watch.
package herder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"

	ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"
)

// Template names an ActorTemplate; its Digest is the fiberd template
// digest the agent resolves.
type Template struct{ Atespace, Name string }

func (t Template) Digest() string { return t.Atespace + "/" + t.Name }

// Grants hands out the grant an actor of a template runs under.
type Grants interface {
	Grant(ctx context.Context, tmpl Template, memoryBytes uint64) (jwt string, g core.Grant, err error)
}

// Router is the ingress in front of fibers: it learns which actor is
// served at which endpoint.
type Router interface {
	Activate(atespace, name, endpoint string)
	Deactivate(atespace, name string)
}

// Config wires the herder.
type Config struct {
	Client *consumer.Client
	Grants Grants
	// Host names the delta registry the agent publishes to; ExportDelta
	// and ImportDelta work there.
	Host   host.Config
	Paths  Paths
	Router Router // optional
	// Probe checks an actor's readiness at its endpoint (default: HTTP
	// GET of the container's readyz path through the fiber's endpoint).
	Probe         func(ctx context.Context, endpoint, path string) error
	CloneDeadline time.Duration
	ReadyTimeout  time.Duration
}

// Payload is what a fiber receives at birth: which actor it is.
type Payload struct {
	Atespace  string `json:"atespace"`
	ActorName string `json:"actor_name"`
	ActorUID  string `json:"actor_uid"`
	Template  string `json:"template"`
}

type actor struct {
	ref      [2]string // atespace, name
	uid      string
	tmpl     Template
	grant    core.Grant
	fiber    consumer.Fiber
	started  time.Time
	spec     *ateompb.WorkloadSpec
	sampleAt time.Time
}

// Service implements ateom.Ateom.
type Service struct {
	ateompb.UnimplementedAteomServer
	cfg Config

	lifecycle sync.Mutex // Run, Checkpoint, Restore and Terminate serialise
	mu        sync.Mutex // active, stats, draining
	active    *actor
	stats     map[string]consumer.Status
	draining  bool
}

func New(cfg Config) *Service {
	if cfg.CloneDeadline <= 0 {
		cfg.CloneDeadline = 30 * time.Second
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 30 * time.Second
	}
	if cfg.Probe == nil {
		cfg.Probe = httpProbe
	}
	return &Service{cfg: cfg, stats: map[string]consumer.Status{}}
}

// Run keeps the stats current from the agent's Watch stream until ctx ends.
func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := s.cfg.Client.Watch(ctx, func(st consumer.Status) {
			s.mu.Lock()
			s.stats[st.GrantUID] = st
			if s.active != nil && s.active.grant.UID == st.GrantUID {
				s.active.sampleAt = time.Now()
			}
			s.mu.Unlock()
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("herder: watch: %v (reconnecting)", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// Drain refuses new actors (a SIGTERM is on its way).
func (s *Service) Drain() {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
}

// Active reports the actor this herder executes, if any.
func (s *Service) Active() (atespace, name, uid string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return "", "", "", false
	}
	return s.active.ref[0], s.active.ref[1], s.active.uid, true
}

func (s *Service) current() *actor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// RunWorkload: a fresh session for the actor.
func (s *Service) RunWorkload(ctx context.Context, req *ateompb.RunWorkloadRequest) (*ateompb.RunWorkloadResponse, error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if err := s.canStart(req.GetActorUid()); err != nil {
		return nil, err
	}
	tmpl := Template{req.GetActorTemplateAtespace(), req.GetActorTemplateName()}
	a, err := s.start(ctx, tmpl, req.GetAtespace(), req.GetActorName(), req.GetActorUid(), uint64(req.GetMemoryBytes()), req.GetSpec(), consumer.Create)
	if err != nil {
		return nil, err
	}
	log.Printf("herder: running %s/%s (%s) as fiber %s on %s", a.ref[0], a.ref[1], a.uid, a.fiber.ID, a.fiber.Endpoint)
	return &ateompb.RunWorkloadResponse{}, nil
}

// RestoreWorkload: the snapshot atelet placed under RestoreStateDir
// becomes this actor's session, resumed.
func (s *Service) RestoreWorkload(ctx context.Context, req *ateompb.RestoreWorkloadRequest) (*ateompb.RestoreWorkloadResponse, error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if err := s.canStart(req.GetActorUid()); err != nil {
		return nil, err
	}
	switch req.GetScope() {
	case ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL:
	default:
		return nil, status.Errorf(codes.FailedPrecondition, "fiberd actors restore from SNAPSHOT_SCOPE_FULL snapshots (process memory); %s is not supported", req.GetScope())
	}
	tmpl := Template{req.GetActorTemplateAtespace(), req.GetActorTemplateName()}
	_, g, err := s.cfg.Grants.Grant(ctx, tmpl, uint64(req.GetMemoryBytes()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "grant for %s: %v", tmpl.Digest(), err)
	}
	dir := s.cfg.Paths.RestoreStateDir(req.GetActorUid())
	if err := host.ImportDelta(ctx, s.cfg.Host, g, req.GetActorUid(), dir); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "import snapshot from %s: %v", dir, err)
	}
	a, err := s.start(ctx, tmpl, req.GetAtespace(), req.GetActorName(), req.GetActorUid(), uint64(req.GetMemoryBytes()), req.GetSpec(), consumer.Resume)
	if err != nil {
		return nil, err
	}
	log.Printf("herder: restored %s/%s (%s) as fiber %s on %s", a.ref[0], a.ref[1], a.uid, a.fiber.ID, a.fiber.Endpoint)
	return &ateompb.RestoreWorkloadResponse{}, nil
}

func (s *Service) canStart(uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return status.Error(codes.Unavailable, "herder is draining")
	}
	if s.active != nil {
		return status.Errorf(codes.FailedPrecondition, "already executing actor %s/%s (%s); one actor per worker", s.active.ref[0], s.active.ref[1], s.active.uid)
	}
	if uid == "" {
		return status.Error(codes.InvalidArgument, "actor_uid is required")
	}
	return nil
}

// start clones the actor's session and expects it to be served the given
// way: a Run must create, a Restore must resume. Anything else is a
// state this herder did not expect and the fiber is let go.
func (s *Service) start(ctx context.Context, tmpl Template, atespace, name, uid string, memory uint64, spec *ateompb.WorkloadSpec, want consumer.Kind) (*actor, error) {
	jwt, g, err := s.cfg.Grants.Grant(ctx, tmpl, memory)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "grant for %s: %v", tmpl.Digest(), err)
	}
	payload, _ := json.Marshal(Payload{Atespace: atespace, ActorName: name, ActorUID: uid, Template: tmpl.Digest()})
	f, err := s.cfg.Client.Clone(ctx, jwt, uid, s.cfg.CloneDeadline, payload)
	if err != nil {
		return nil, toStatus(err)
	}
	if f.Kind != want {
		_ = s.cfg.Client.Release(ctx, f.ID, want == consumer.Resume)
		return nil, status.Errorf(codes.Internal, "clone of %s served %s, want %s", uid, f.Kind, want)
	}
	if err := s.ready(ctx, f.Endpoint, spec); err != nil {
		_ = s.cfg.Client.Release(ctx, f.ID, true)
		return nil, status.Errorf(codes.Unavailable, "actor %s not ready: %v", uid, err)
	}
	a := &actor{ref: [2]string{atespace, name}, uid: uid, tmpl: tmpl, grant: g, fiber: f, started: time.Now(), spec: spec}
	s.mu.Lock()
	s.active = a
	s.mu.Unlock()
	if s.cfg.Router != nil {
		s.cfg.Router.Activate(atespace, name, f.Endpoint)
	}
	return a, nil
}

// ready waits for the containers' readyz probes on the fiber's endpoint
// (one fiber serves the actor; every container's path is probed there).
func (s *Service) ready(ctx context.Context, endpoint string, spec *ateompb.WorkloadSpec) error {
	for _, c := range spec.GetContainers() {
		rz := c.GetReadyz()
		if rz == nil {
			continue
		}
		path := rz.GetHttpGet().GetPath()
		if path == "" {
			path = "/readyz"
		}
		timeout := s.cfg.ReadyTimeout
		if rz.GetTimeoutSeconds() > 0 {
			timeout = time.Duration(rz.GetTimeoutSeconds()) * time.Second
		}
		deadline := time.Now().Add(timeout)
		for {
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := s.cfg.Probe(pctx, endpoint, path)
			cancel()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("container %s: %s did not answer 200 within %s: %w", c.GetName(), path, timeout, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return nil
}

// CheckpointWorkload: park, then the session leaves as files atelet ships.
func (s *Service) CheckpointWorkload(ctx context.Context, req *ateompb.CheckpointWorkloadRequest) (*ateompb.CheckpointWorkloadResponse, error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	a := s.current()
	if a == nil || a.uid != req.GetActorUid() {
		return nil, status.Errorf(codes.NotFound, "actor %s is not executing here", req.GetActorUid())
	}
	if req.GetScope() != ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL {
		return nil, status.Errorf(codes.FailedPrecondition, "fiberd checkpoints are SNAPSHOT_SCOPE_FULL (process memory); %s is not supported", req.GetScope())
	}
	if s.cfg.Router != nil {
		s.cfg.Router.Deactivate(a.ref[0], a.ref[1])
	}
	if err := s.cfg.Client.Park(ctx, a.fiber.ID, true); err != nil {
		if s.cfg.Router != nil {
			s.cfg.Router.Activate(a.ref[0], a.ref[1], a.fiber.Endpoint)
		}
		return nil, toStatus(err)
	}
	dir := s.cfg.Paths.CheckpointStateDir(a.uid)
	files, err := host.ExportDelta(ctx, s.cfg.Host, a.grant, a.uid, dir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "export parked session %s: %v", a.uid, err)
	}
	s.mu.Lock()
	s.active = nil
	s.mu.Unlock()
	log.Printf("herder: checkpointed %s/%s (%s): %v in %s", a.ref[0], a.ref[1], a.uid, files, dir)
	return &ateompb.CheckpointWorkloadResponse{SnapshotFiles: files}, nil
}

// TerminateWorkload ends the actor and discards its state here.
func (s *Service) TerminateWorkload(ctx context.Context, req *ateompb.TerminateWorkloadRequest) (*ateompb.TerminateWorkloadResponse, error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	a := s.current()
	if a == nil || a.uid != req.GetActorUid() {
		return &ateompb.TerminateWorkloadResponse{}, nil // nothing to stop is stopped
	}
	if s.cfg.Router != nil {
		s.cfg.Router.Deactivate(a.ref[0], a.ref[1])
	}
	if err := s.cfg.Client.Release(ctx, a.fiber.ID, true); err != nil && !consumer.NotFound(err) {
		return nil, toStatus(err)
	}
	s.mu.Lock()
	s.active = nil
	s.mu.Unlock()
	log.Printf("herder: terminated %s/%s (%s)", a.ref[0], a.ref[1], a.uid)
	return &ateompb.TerminateWorkloadResponse{}, nil
}

// GetWorkloadStats answers for the actor the caller names: NOT_FOUND
// when it is not here, FAILED_PRECONDITION when there is no sample yet.
func (s *Service) GetWorkloadStats(_ context.Context, req *ateompb.GetWorkloadStatsRequest) (*ateompb.GetWorkloadStatsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.uid != req.GetActorUid() {
		return nil, status.Errorf(codes.NotFound, "actor %s is not executing here", req.GetActorUid())
	}
	sample, ok := s.sampleLocked(s.active)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no sample yet")
	}
	return &ateompb.GetWorkloadStatsResponse{Sample: sample}, nil
}

// GetActiveWorkloadStats samples whatever executes here, never an error
// for an ordinary state.
func (s *Service) GetActiveWorkloadStats(context.Context, *ateompb.GetActiveWorkloadStatsRequest) (*ateompb.GetActiveWorkloadStatsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return &ateompb.GetActiveWorkloadStatsResponse{Result: &ateompb.GetActiveWorkloadStatsResponse_NoSampleReason{NoSampleReason: ateompb.NoSampleReason_NO_SAMPLE_REASON_NO_WORKLOAD}}, nil
	}
	sample, ok := s.sampleLocked(s.active)
	if !ok {
		return &ateompb.GetActiveWorkloadStatsResponse{Result: &ateompb.GetActiveWorkloadStatsResponse_NoSampleReason{NoSampleReason: ateompb.NoSampleReason_NO_SAMPLE_REASON_NOT_MEASURABLE_YET}}, nil
	}
	return &ateompb.GetActiveWorkloadStatsResponse{Result: &ateompb.GetActiveWorkloadStatsResponse_Sample{Sample: sample}}, nil
}

// sampleLocked: the actor's W as the agent last reported it for its
// grant (one actor per grant here, so the grant's W is the actor's).
func (s *Service) sampleLocked(a *actor) (*ateompb.WorkloadStatsSample, bool) {
	st, ok := s.stats[a.grant.UID]
	if !ok || a.sampleAt.IsZero() {
		return nil, false
	}
	return &ateompb.WorkloadStatsSample{
		Atespace: a.ref[0], ActorName: a.ref[1], ActorUid: a.uid,
		ActorTemplateAtespace: a.tmpl.Atespace, ActorTemplateName: a.tmpl.Name,
		Source:                ateompb.StatsSource_STATS_SOURCE_CGROUP,
		MemoryCurrentBytes:    st.WUsedBytes,
		MemoryWorkingSetBytes: st.WUsedBytes,
		ObservedAtUnixNano:    a.sampleAt.UnixNano(),
	}, true
}

// toStatus maps the consumer's typed errors onto the codes Substrate's
// router parks on: a miss is ResourceExhausted (capacity) or Unavailable
// (control plane), a tier gap is FailedPrecondition.
func toStatus(err error) error {
	var shed *consumer.Shed
	var def *consumer.Deferred
	var gap *consumer.TierGap
	switch {
	case errors.As(err, &shed):
		return status.Errorf(codes.Unavailable, "%v", err)
	case errors.As(err, &def):
		return status.Errorf(codes.ResourceExhausted, "%v", err)
	case errors.As(err, &gap):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Errorf(codes.Internal, "%v", err)
}

// httpProbe GETs path on the fiber's endpoint and wants a 200.
func httpProbe(ctx context.Context, endpoint, path string) error {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return fiberendpoint.Dial(ctx, endpoint)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://fiber"+path, nil)
	if err != nil {
		return err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// TemplateKey is how a -template entry names an ActorTemplate:
// "<atespace>/<name>" (or "default" for every other one).
func TemplateKey(atespace, name string) string {
	return strings.TrimSpace(atespace) + "/" + strings.TrimSpace(name)
}
