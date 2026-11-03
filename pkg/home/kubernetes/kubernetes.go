// Package kubernetes is fiberd's home in a Kubernetes grant Pod, where
// fiberd is the Pod's one container. Grants arrive as *.jwt files in a
// directory projected into the Pod. Control-plane liveness is the API
// server answering for the Pod. Readiness is a Pod condition a readiness
// gate waits on, set once a template is warm. The cgroup subtree is the
// Pod's own, under the kubelet's ceiling. Endpoints are the Pod's IP, and
// the device channel is the Pod's ResourceClaim. Scope is what the Pod is,
// namespace, service account, node and claims, and the home loses it when
// the Pod is gone, replaced or terminating, the namespace terminates, a
// claim is deleted under a live Pod, or the cluster has not served the
// claims for the stale TTL.
//
// The production controller that creates grant Pods is a separate
// project. It lists PodConditionZygoteReady as a readiness gate on every
// grant Pod and writes the grants directory.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/grantdir"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// Name is what this home is selected by.
const Name = "kubernetes"

const (
	// DefaultStaleTTL is how long the API server may go without answering
	// for the Pod before the home counts as unhealthy.
	DefaultStaleTTL = 30 * time.Second
	// DefaultGrantsPoll is how often the grants directory is read.
	DefaultGrantsPoll = 2 * time.Second
	// cgroupMount is where the Pod's cgroup v2 hierarchy is mounted.
	cgroupMount = "/sys/fs/cgroup"
)

// Config is what cmd/fiberd hands New.
type Config struct {
	// Kube is the cluster. Required.
	Kube Kube
	// PodName and PodNamespace name this Pod. Required.
	PodName      string
	PodNamespace string
	// PodUID is this Pod's UID. Required. A Pod read with another UID is
	// a replacement, and the scope is lost.
	PodUID string
	// StaleTTL is how long the API server may go without answering for
	// the Pod before the home is unhealthy. Default DefaultStaleTTL.
	StaleTTL time.Duration
	// Poll is how often the API server is asked. It is also how long one
	// round may take. Default half of StaleTTL.
	Poll time.Duration
	// GrantsDir is the projected directory polled for *.jwt files. Empty
	// means no delivery, and grants then arrive only inside Clone requests.
	GrantsDir string
	// GrantsPoll is how often GrantsDir is read. Default DefaultGrantsPoll.
	GrantsPoll time.Duration
	// Cache is the verifier's key cache, refreshed in the background while
	// the home runs. Nil means no issuer keys to refresh.
	Cache *grant.Cache
	// Family picks which Pod IP callers dial. Unix means fibers are
	// reachable from inside the Pod only, and no address is advertised.
	Family endpoint.Family
	// Devices is what the device driver exposed to this Pod, device paths
	// or ids, handed to every grant's engine as its device channel.
	Devices []string
	// CgroupRoot is the cgroup v2 subtree fiberd may carve. Empty means
	// the cgroup this process runs in, under /sys/fs/cgroup.
	CgroupRoot string
	// Clock drives the polls and stamps the health. Default the real
	// clock.
	Clock clock.WithTicker
	// Logger receives the home's log lines. Default klog's.
	Logger logr.Logger
}

// withDefaults is cfg with every empty optional field filled.
func (c Config) withDefaults() Config {
	if c.StaleTTL == 0 {
		c.StaleTTL = DefaultStaleTTL
	}
	if c.Poll == 0 {
		c.Poll = c.StaleTTL / 2
	}
	if c.GrantsPoll == 0 {
		c.GrantsPoll = DefaultGrantsPoll
	}
	if c.Clock == nil {
		c.Clock = clock.RealClock{}
	}
	if c.Logger.GetSink() == nil {
		c.Logger = klog.Background()
	}
	return c
}

// Validate reports the first thing wrong with c, after defaults.
func (c Config) Validate() error {
	c = c.withDefaults()
	switch {
	case c.Kube == nil:
		return errors.New("kubernetes home: a cluster client is required")
	case c.PodName == "":
		return errors.New("kubernetes home: the Pod name is required")
	case c.PodNamespace == "":
		return errors.New("kubernetes home: the Pod namespace is required")
	case c.PodUID == "":
		return errors.New("kubernetes home: the Pod UID is required")
	case c.StaleTTL < 0:
		return fmt.Errorf("kubernetes home: stale TTL %s is negative", c.StaleTTL)
	case c.Poll < 0:
		return fmt.Errorf("kubernetes home: poll interval %s is negative", c.Poll)
	case c.Poll >= c.StaleTTL:
		return fmt.Errorf("kubernetes home: poll interval %s is not shorter than the stale TTL %s", c.Poll, c.StaleTTL)
	case c.GrantsPoll < 0:
		return fmt.Errorf("kubernetes home: grants poll interval %s is negative", c.GrantsPoll)
	}
	switch c.Family {
	case "", endpoint.Unix, endpoint.Inet4, endpoint.Inet6:
	default:
		return fmt.Errorf("kubernetes home: unknown endpoint family %q", c.Family)
	}
	return nil
}

// Home is the Kubernetes home. It implements home.Home, and the optional
// fiberd.ScopeLoser, fiberd.EndpointHoster and the issuer override behind
// the admin socket.
type Home struct {
	cfg        Config
	log        logr.Logger
	health     *core.SourceHealth
	cgroupRoot string

	// stop ends what New started, the wait for the Pod's address. Close
	// cancels it, and so does Run when its context ends.
	stopCtx context.Context
	stop    context.CancelFunc
	started atomic.Bool

	losses home.ScopeLossQueue
	gate   home.ReadyGate
	poll   *home.HealthPoll

	// mu guards what the last fully answered round stored, and the clock
	// of the claims going unreadable.
	mu     sync.Mutex
	self   *corev1.Pod       // the last Pod stored, nil before the first
	claims []string          // the ResourceClaims the stored Pod names, sorted
	scope  []core.ScopeClaim // the snapshot of the stored Pod, nil before the first
	// unreadableSince is when the cluster first answered that it serves
	// no ResourceClaims. Zero while the claims are readable.
	unreadableSince time.Time
}

// New builds the home. It reads nothing from the cluster. The first
// read happens in EndpointHost, Devices or the first poll round. The
// health starts in sync, so a Pod the API server has not answered for
// yet is not unhealthy before the stale TTL has passed.
func New(cfg Config) (*Home, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	h := &Home{
		cfg:        cfg,
		log:        cfg.Logger.WithValues("home", Name),
		health:     core.NewSourceHealth(cfg.StaleTTL, cfg.Clock.Now()),
		cgroupRoot: cfg.CgroupRoot,
	}
	if h.cgroupRoot == "" {
		h.cgroupRoot = cgroup.Own(cgroupMount).Path
	}
	h.stopCtx, h.stop = context.WithCancel(context.Background())
	h.gate.Publish = h.publishGate
	h.poll = &home.HealthPoll{
		Health: h.health, Every: cfg.Poll, Clock: cfg.Clock, Round: h.round,
		OnError:     func(err error) { h.log.Error(err, "API server did not answer") },
		OnRecovered: func() { h.log.Info("API server answered again") },
	}
	return h, nil
}

func (h *Home) Name() string               { return Name }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.cgroupRoot }

// Ready reports whether any grant's template is warm, which is what the
// Pod condition says once it is published.
func (h *Home) Ready() bool { return h.gate.Ready() }

// Grants polls the projected directory. A new or changed *.jwt file is
// GrantAdded, a removed one GrantRemoved.
func (h *Home) Grants(ctx context.Context) (<-chan home.GrantEvent, error) {
	if h.cfg.GrantsDir == "" {
		return nil, nil
	}
	return grantdir.Poll(ctx, h.cfg.GrantsDir, h.cfg.GrantsPoll)
}

// Scope is the facts the Pod is made of. Before the first Pod is stored
// it holds what the configuration knows, the namespace, the Pod name and
// its UID. A stored Pod adds the service account, the node and one claim
// per ResourceClaim.
func (h *Home) Scope() []core.ScopeClaim {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.scope == nil {
		return scopeOf(h.cfg, nil, nil)
	}
	return append([]core.ScopeClaim(nil), h.scope...)
}

// Devices is the Pod's ResourceClaim with the devices the driver
// exposed, a static set when the Pod has devices but no claim, and
// nothing otherwise. The claim is the Pod's, so there is nothing to
// release per grant. The Pod is read first when it has not been yet.
// A failed read never fails the admission, since fiberd does not retry
// one until the grant changes. The answer is then the static set, or no
// channel without devices.
func (h *Home) Devices(ctx context.Context, _ core.Grant) (core.DeviceChannel, func(), error) {
	ch := core.DeviceChannel{Devices: append([]string(nil), h.cfg.Devices...)}
	if len(ch.Devices) > 0 {
		ch.Kind = "static"
	}
	if _, err := h.pod(ctx); err != nil {
		h.log.Info("Answered the device channel without the Pod", "reason", err)
		return ch, func() {}, nil
	}
	h.mu.Lock()
	claims := h.claims
	h.mu.Unlock()
	if len(claims) > 0 {
		ch.Kind, ch.Detail = "dra", joinClaims(claims)
	}
	return ch, func() {}, nil
}

// PublishReady records that the grant's template is warm, or no longer
// is, and sets the Pod condition when that flips "any template is warm".
func (h *Home) PublishReady(ctx context.Context, grantUID string, ready bool) error {
	err := h.gate.PublishReady(ctx, grantUID, ready)
	if err != nil {
		h.log.Error(err, "Readiness gate not set, the next poll round retries", "grant", grantUID, "ready", ready)
	}
	return err
}

// OnScopeLost sets what is called, once per reason and on a goroutine of
// the home's own, when the Pod's scope goes away under it. fiberd wires
// its epoch bump.
func (h *Home) OnScopeLost(fn func(ctx context.Context, reason string)) {
	h.losses.OnScopeLost(fn)
}

// SetIssuerReachable is the test-only override behind fiberd's admin
// socket. false marks the API server unreachable now and keeps it so.
// true resumes the polls and marks it reachable. The pause comes first,
// and it waits for a round marking the health, so the mark here is the
// last one.
func (h *Home) SetIssuerReachable(reachable bool) {
	h.poll.SetPaused(!reachable)
	now := h.cfg.Clock.Now()
	if reachable {
		h.health.MarkSync(now)
	} else {
		h.health.MarkSync(now.Add(-h.cfg.StaleTTL))
	}
	h.log.Info("Issuer reachability overridden", "reachable", reachable)
}

// Run drives the liveness poll, the delivery of scope losses and the key
// cache refresh until ctx ends. It returns only once all of them have
// stopped. A second Run logs and returns at once, as a shared
// informer does.
func (h *Home) Run(ctx context.Context) {
	if !h.started.CompareAndSwap(false, true) {
		h.log.Info("Run called again, the second call does nothing")
		return
	}
	defer h.stop()
	unhook := context.AfterFunc(ctx, h.stop)
	defer unhook()
	var wg sync.WaitGroup
	wg.Go(func() { h.losses.Run(ctx) })
	wg.Go(func() { h.poll.Run(ctx) })
	if h.cfg.Cache != nil {
		wg.Go(func() { h.cfg.Cache.Run(ctx, h.cfg.StaleTTL/2) })
	}
	wg.Wait()
}

// Close ends what New started, the wait for the Pod's address in
// EndpointHost. Run's context ends everything else.
func (h *Home) Close() { h.stop() }

var _ home.Home = (*Home)(nil)
