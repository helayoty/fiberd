// Package kubernetes is fiberd's home in a Kubernetes grant Pod, where
// fiberd is the Pod's one container. The home fetches the Pod's grant
// from the controller with the Pod's bound service-account token, renews
// it at half its lease and writes it into the grants directory. The
// directory is polled for *.jwt files, so a grant another writer drops
// there is read too. Without a token file, grants arrive only as such
// files.
//
// Control-plane liveness is the API server answering for the Pod.
// Readiness is a Pod condition a readiness gate waits on, set once a
// template is warm. The cgroup subtree is the Pod's own, under the
// kubelet's ceiling. Endpoints are the Pod's IP, and the device channel
// is the Pod's ResourceClaim. Scope is what the Pod is, namespace,
// service account, node and claims, and the home loses it when the Pod
// is gone, replaced or terminating, the namespace terminates, a claim is
// deleted under a live Pod, or the cluster has not served the claims for
// the stale TTL.
//
// The production controller that creates grant Pods is a separate
// project. It lists PodConditionZygoteReady as a readiness gate on every
// grant Pod and serves the grants the home fetches.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/endpoint"
	"github.com/Azure/fiberd/pkg/grant"
	"github.com/Azure/fiberd/pkg/home"
	"github.com/Azure/fiberd/pkg/home/grantdir"
	"github.com/Azure/fiberd/pkg/sys/cgroup"
)

// Name is what this home is selected by.
const Name = "kubernetes"

const (
	// DefaultStaleTTL is how long the API server may go without answering
	// for the Pod before the home counts as unhealthy.
	DefaultStaleTTL = 30 * time.Second
	// DefaultGrantsPoll is how often the grants directory is read.
	DefaultGrantsPoll = 2 * time.Second
	// DefaultGrantFetchTimeout is how long New retries the first grant
	// fetch.
	DefaultGrantFetchTimeout = 60 * time.Second
	// cgroupMount is where the Pod's cgroup v2 hierarchy is mounted.
	cgroupMount = "/sys/fs/cgroup"
)

// delegateOwn readies the cgroup fiberd runs in for the runtime to carve
// grants under. That cgroup holds fiberd itself, and cgroup v2 enables no
// controller for the children of a cgroup with processes, so fiberd moves
// into a leaf first, as the Slurm and substrate homes do. Tests replace it.
var delegateOwn = func() (cgroup.Dir, error) { return cgroup.Delegate(cgroup.Own(cgroupMount)) }

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
	// GrantsDir is the directory polled for *.jwt files, and the one the
	// grant fetch writes. Empty means no delivery and no grant to admit.
	// fiberd refuses to start this home so, unless a test-hooks build runs
	// under -admin-unsafe, where grants arrive inside Clone requests.
	GrantsDir string
	// GrantsPoll is how often GrantsDir is read. Default DefaultGrantsPoll.
	GrantsPoll time.Duration
	// GrantTokenFile is the path of the Pod's bound service-account
	// token, sent to fetch the Pod's grant. Empty means no fetch, and
	// grants arrive only as files. Set, it needs GrantIssuerURL and
	// GrantsDir.
	GrantTokenFile string
	// GrantIssuerURL is the issuer, the controller. Grants are fetched
	// from it with "/v1/grant" appended. It must be https when the fetch
	// is on.
	GrantIssuerURL string
	// GrantCAFile is the PEM CA bundle the grant endpoint's certificate
	// must chain to. Empty means the system roots.
	GrantCAFile string
	// GrantFetchTimeout is how long New retries the first grant fetch.
	// Default DefaultGrantFetchTimeout.
	GrantFetchTimeout time.Duration
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
	// the cgroup this process runs in, under /sys/fs/cgroup, delegated:
	// fiberd moves into its `fiberd` leaf and carves under its `grants`
	// child.
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
	if c.GrantFetchTimeout == 0 {
		c.GrantFetchTimeout = DefaultGrantFetchTimeout
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
	case c.GrantTokenFile != "" && c.GrantIssuerURL == "":
		return errors.New("kubernetes home: a grant token file needs the issuer URL")
	case c.GrantTokenFile != "" && c.GrantsDir == "":
		return errors.New("kubernetes home: a grant token file needs the grants directory")
	case c.GrantTokenFile != "" && !isHTTPS(c.GrantIssuerURL):
		return fmt.Errorf("kubernetes home: issuer URL %q is not https, and the grant fetch sends the Pod's token to it", c.GrantIssuerURL)
	case c.GrantFetchTimeout < 0:
		return fmt.Errorf("kubernetes home: grant fetch timeout %s is negative", c.GrantFetchTimeout)
	}
	switch c.Family {
	case "", endpoint.Unix, endpoint.Inet4, endpoint.Inet6:
	default:
		return fmt.Errorf("kubernetes home: unknown endpoint family %q", c.Family)
	}
	return nil
}

// isHTTPS reports whether raw parses as an https URL with a host.
func isHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// Home is the Kubernetes home. It implements home.Home, and the optional
// fiberd.ScopeLoser, fiberd.EndpointHoster and the issuer override behind
// the admin socket.
type Home struct {
	cfg        Config
	log        logr.Logger
	health     *core.SourceHealth
	cgroupRoot string

	// stop ends what New started, the first grant fetch and the wait for
	// the Pod's address. Close cancels it, and so does Run when its
	// context ends. New's own context ends only the first fetch.
	stopCtx context.Context
	stop    context.CancelFunc
	started atomic.Bool

	losses home.ScopeLossQueue
	gate   home.ReadyGate
	poll   *home.HealthPoll
	// fetch renews the Pod's grant. Nil without a grant token file.
	fetch *fetcher

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
//
// With a grant token file, New fetches the Pod's grant before it
// returns, retrying for up to GrantFetchTimeout. It fails when no grant
// came by then, unless the grants directory holds an unexpired grant
// file for the Pod. Run renews the grant from there.
//
// ctx bounds New's own work, which is the first grant fetch. When ctx
// ends first, New closes the home and returns ctx's cause. ctx is not
// the home's lifetime. Run's context and Close end the home once New
// has returned it.
func New(ctx context.Context, cfg Config) (*Home, error) { return newHome(ctx, cfg, nil) }

// newHome is New. built, when set, is handed the home before the first
// grant fetch.
func newHome(ctx context.Context, cfg Config, built func(*Home)) (*Home, error) {
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
		root, err := delegateOwn()
		if err != nil {
			return nil, fmt.Errorf("kubernetes home: %w", err)
		}
		h.cgroupRoot = root.Path
	}
	h.stopCtx, h.stop = context.WithCancel(context.Background())
	h.gate.Publish = h.publishGate
	h.poll = &home.HealthPoll{
		Health: h.health, Every: cfg.Poll, Clock: cfg.Clock, Round: h.round,
		OnError:     func(err error) { h.log.Error(err, "API server did not answer") },
		OnRecovered: func() { h.log.Info("API server answered again") },
	}
	if cfg.GrantTokenFile == "" {
		return h, nil
	}
	f, err := newFetcher(cfg, h.log)
	if err != nil {
		h.stop()
		return nil, fmt.Errorf("kubernetes home: %w", err)
	}
	h.fetch = f
	if built != nil {
		built(h)
	}
	// The first fetch ends on Close or when the caller's ctx ends,
	// whichever comes first. Only Close ends the home's own context.
	startCtx, cancel := context.WithCancel(h.stopCtx)
	stopAfter := context.AfterFunc(ctx, cancel)
	err = f.start(startCtx, cfg.GrantFetchTimeout)
	stopAfter()
	cancel()
	if err != nil {
		h.stop()
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			// The caller's ctx cancelled the fetch. Its cause is the error
			// to return, so a deadline reads as one.
			return nil, fmt.Errorf("kubernetes home: first grant fetch: %w", context.Cause(ctx))
		}
		return nil, err
	}
	return h, nil
}

func (h *Home) Name() string               { return Name }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.cgroupRoot }

// SelfAdmitUID is the Pod UID, since the controller issues this Pod's
// grant under it and a token for an earlier Pod of the same name must not
// self-admit here.
func (h *Home) SelfAdmitUID() string { return h.cfg.PodUID }

// OwnGrant is the Pod's own grant, the file the grant fetch wrote. Clone
// admits it on the Pod UID in place of the token presented. A home
// without a grant fetch holds none.
func (h *Home) OwnGrant() ([]byte, bool) {
	if h.fetch == nil {
		return nil, false
	}
	tok, _, ok := h.fetch.held()
	if !ok {
		return nil, false
	}
	return []byte(tok), true
}

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

// Run drives the liveness poll, the delivery of scope losses, the key
// cache refresh and the grant renewal until ctx ends. It returns only
// once all of them have stopped. A second Run logs and returns at once,
// as a shared informer does.
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
	if h.fetch != nil {
		wg.Go(func() { h.fetch.run(ctx) })
	}
	wg.Wait()
}

// Close ends what New started, the wait for the Pod's address in
// EndpointHost. Run's context ends everything else.
func (h *Home) Close() { h.stop() }

var _ home.Home = (*Home)(nil)
