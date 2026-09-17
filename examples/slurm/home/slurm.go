// Package home is the Slurm home: the agent runs inside an allocation,
// started by the job (or its prolog) after the grant was verified. It is
// the integration point with fiberd: everything fiberd needs from an
// environment is the home.Home interface (pkg/home) plus the optional
// interfaces pkg/agent looks for, and this package implements them from
// what Slurm tells a job through its environment and scontrol.
//
// Grants are *.jwt files in a directory the launcher (or prolog) fills;
// control-plane liveness is slurmctld answering for the job; readiness is
// the allocation's own state plus the Watch stream; the cgroup subtree is
// the job step's (task/cgroup's memory limit on it is the block ceiling);
// endpoints are the node's address; the fabric channel is the
// allocation's GRES; scope claims are the job, user, account, partition,
// node and GRES. A grant asking for more fibers than the allocation has
// CPUs is refused. The job leaving RUNNING while the agent lives is scope
// loss, and the agent bumps its epoch.
package home

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/filelane"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

type Config struct {
	// Env reads the job's environment (SLURM_*); nil means os.Getenv.
	Env func(string) string
	// GrantsDir is polled for *.jwt files; default
	// /run/fiberd/job-<id>/grants, which the launcher fills.
	GrantsDir string
	Poll      time.Duration
	// StaleTTL: slurmctld not answering for the job this long is unhealthy.
	StaleTTL time.Duration
	// CgroupMount is the cgroup v2 mount (default /sys/fs/cgroup); the
	// job step's cgroup under it gets a `fiberd` subtree.
	CgroupMount string
	// Devices overrides what the allocation's GRES exposes (default: the
	// GPUs Slurm names in CUDA_VISIBLE_DEVICES or SLURM_JOB_GPUS, as
	// /dev/nvidia<n>).
	Devices []string
	// Family and Host pick the address callers dial (Host empty: the
	// node's address of that family).
	Family endpoint.Family
	Host   string
	// ListenPort is the agent's gRPC port, for the advertised endpoint.
	ListenPort string
	// Probe is the command whose output carries the job's state as
	// JobState=<STATE> (default: scontrol show job -o <id>); nil disables
	// the probe and liveness comes from a timer, as on a standalone host
	// without an issuer.
	Probe []string
	// OnJobEnd runs after the scope-loss hook when the job reached a
	// terminal state: the allocation is over, so is the agent. Default:
	// SIGTERM to this process, which the agent takes as a graceful stop
	// (slurmstepd kills the step's own cgroups, not the ones fiberd made
	// beneath them, so the agent must leave on its own).
	OnJobEnd func()
}

// Job is what the allocation says about itself.
type Job struct {
	ID, Name, User, Account, Partition string
	Node, NodeList, GRES               string
	CPUs                               int
}

type Home struct {
	cfg        Config
	job        Job
	health     *core.SourceHealth
	scope      []core.ScopeClaim
	cgroupRoot string
	devices    []string

	mu        sync.Mutex
	paused    bool
	lost      string
	scopeLost func(ctx context.Context, reason string)
}

func New(cfg Config) (*Home, error) {
	if cfg.Env == nil {
		cfg.Env = os.Getenv
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 30 * time.Second
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.CgroupMount == "" {
		cfg.CgroupMount = "/sys/fs/cgroup"
	}
	job, err := ReadJob(cfg.Env)
	if err != nil {
		return nil, err
	}
	if cfg.GrantsDir == "" {
		cfg.GrantsDir = DefaultGrantsDir(job.ID)
	}
	if cfg.Probe == nil {
		cfg.Probe = []string{"scontrol", "show", "job", "-o", job.ID}
	}
	if cfg.OnJobEnd == nil {
		cfg.OnJobEnd = func() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) }
	}
	h := &Home{cfg: cfg, job: job, health: core.NewSourceHealth(cfg.StaleTTL, time.Now())}
	h.devices = cfg.Devices
	if len(h.devices) == 0 {
		h.devices = gpuDevices(cfg.Env)
	}
	h.scope = h.buildScope()
	root, err := cgroup.Delegate(cgroup.Own(cfg.CgroupMount))
	if err != nil {
		return nil, fmt.Errorf("slurm: %w", err)
	}
	h.cgroupRoot = root.Path
	return h, nil
}

// DefaultGrantsDir is where the launcher and the prolog put a job's
// grants.
func DefaultGrantsDir(jobID string) string {
	return filepath.Join("/run/fiberd", "job-"+jobID, "grants")
}

// ReadJob reads the allocation from the environment Slurm gives a job.
func ReadJob(env func(string) string) (Job, error) {
	j := Job{
		ID:        env("SLURM_JOB_ID"),
		Name:      env("SLURM_JOB_NAME"),
		User:      env("SLURM_JOB_USER"),
		Account:   env("SLURM_JOB_ACCOUNT"),
		Partition: env("SLURM_JOB_PARTITION"),
		Node:      env("SLURMD_NODENAME"),
		NodeList:  env("SLURM_JOB_NODELIST"),
		GRES:      env("SLURM_JOB_GRES"),
	}
	if j.ID == "" {
		return Job{}, errors.New("slurm: not inside an allocation (SLURM_JOB_ID unset)")
	}
	if j.User == "" {
		j.User = env("USER")
	}
	if j.Node == "" {
		j.Node, _ = os.Hostname()
	}
	if s := env("SLURM_CPUS_ON_NODE"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return Job{}, fmt.Errorf("slurm: SLURM_CPUS_ON_NODE=%q: %w", s, err)
		}
		j.CPUs = n
	}
	return j, nil
}

// gpuDevices: the GPUs Slurm's gres/gpu plugin exposes to the job.
func gpuDevices(env func(string) string) []string {
	list := env("CUDA_VISIBLE_DEVICES")
	if list == "" {
		list = env("SLURM_JOB_GPUS")
	}
	var out []string
	for _, id := range strings.Split(list, ",") {
		if id = strings.TrimSpace(id); id != "" {
			if _, err := strconv.Atoi(id); err == nil {
				id = "/dev/nvidia" + id
			}
			out = append(out, id)
		}
	}
	return out
}

func (h *Home) buildScope() []core.ScopeClaim {
	s := []core.ScopeClaim{{Name: "job_id", Value: h.job.ID}}
	for _, c := range []core.ScopeClaim{
		{Name: "job_name", Value: h.job.Name},
		{Name: "user", Value: h.job.User},
		{Name: "account", Value: h.job.Account},
		{Name: "partition", Value: h.job.Partition},
		{Name: "node", Value: h.job.Node},
		{Name: "nodelist", Value: h.job.NodeList},
		{Name: "gres", Value: h.job.GRES},
	} {
		if c.Value != "" {
			s = append(s, c)
		}
	}
	if h.job.CPUs > 0 {
		s = append(s, core.ScopeClaim{Name: "cpus", Value: strconv.Itoa(h.job.CPUs)})
	}
	return s
}

func (h *Home) Name() string               { return "slurm" }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.cgroupRoot }
func (h *Home) Job() Job                   { return h.job }

// EndpointHost is the node's address of the configured family: the
// configured host, else what the node name resolves to, else the first
// non-loopback address of the family on this host.
func (h *Home) EndpointHost() string {
	if h.cfg.Host != "" {
		return h.cfg.Host
	}
	want := h.cfg.Family
	if want == endpoint.Unix || want == "" {
		want = endpoint.Inet4
	}
	fits := func(ip net.IP) bool {
		return ip != nil && !ip.IsLoopback() && (ip.To4() != nil) == (want == endpoint.Inet4)
	}
	if h.job.Node != "" {
		if ips, err := net.LookupIP(h.job.Node); err == nil {
			for _, ip := range ips {
				if fits(ip) {
					return ip.String()
				}
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && fits(n.IP) && (n.IP.To4() != nil || n.IP.IsGlobalUnicast()) {
				return n.IP.String()
			}
		}
	}
	return ""
}

// AdvertisedEndpoint is where callers reach this agent.
func (h *Home) AdvertisedEndpoint() string {
	host := h.EndpointHost()
	if host == "" || h.cfg.ListenPort == "" {
		return ""
	}
	return net.JoinHostPort(host, h.cfg.ListenPort)
}

// Scope: the facts the allocation is made of.
func (h *Home) Scope() []core.ScopeClaim { return append([]core.ScopeClaim(nil), h.scope...) }

// Fabric: the allocation's GRES, with the devices Slurm exposed. The
// allocation is also the capacity bound: a grant asking for more fibers
// than it has CPUs is refused here, before its template is warmed.
func (h *Home) Fabric(_ context.Context, g core.Grant) (core.FabricChannel, func(), error) {
	if h.job.CPUs > 0 && g.FiberMax > h.job.CPUs {
		return core.FabricChannel{}, nil, fmt.Errorf("slurm: grant %s asks for %d fibers; job %s has %d CPUs", g.UID, g.FiberMax, h.job.ID, h.job.CPUs)
	}
	fc := core.FabricChannel{Devices: append([]string(nil), h.devices...)}
	switch {
	case h.job.GRES != "":
		fc.Kind, fc.Detail = "gres", h.job.GRES
	case len(fc.Devices) > 0:
		fc.Kind = "static"
	}
	return fc, func() {}, nil
}

// Grants is the job's grants directory.
func (h *Home) Grants(ctx context.Context) (<-chan home.GrantEvent, error) {
	return filelane.Poll(ctx, h.cfg.GrantsDir, h.cfg.Poll)
}

// PublishReady: readiness under Slurm is the allocation's own state plus
// the Watch stream; nothing to publish.
func (h *Home) PublishReady(context.Context, string, bool) error { return nil }

// OnScopeLost sets what to call (once per reason) when the job leaves
// RUNNING under a live agent: cmd/fiberd-slurm wires Agent.BumpEpoch.
func (h *Home) OnScopeLost(fn func(ctx context.Context, reason string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopeLost = fn
}

// SetLane is the test-only override behind fiberd's admin socket.
func (h *Home) SetLane(healthy bool) {
	h.mu.Lock()
	h.paused = !healthy
	h.mu.Unlock()
	if healthy {
		h.health.MarkSync(time.Now())
	} else {
		h.health.MarkSync(time.Now().Add(-h.cfg.StaleTTL))
	}
	log.Printf("slurm: grant lane set healthy=%v", healthy)
}

var jobState = regexp.MustCompile(`\bJobState=([A-Z_]+)`)

// Run probes slurmctld for the job every StaleTTL/2: an answer with the
// job RUNNING is liveness; any terminal state is scope loss.
func (h *Home) Run(ctx context.Context) {
	every := h.cfg.StaleTTL / 2
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *Home) poll(ctx context.Context) {
	h.mu.Lock()
	paused := h.paused
	h.mu.Unlock()
	if len(h.cfg.Probe) == 0 {
		if !paused {
			h.health.MarkSync(time.Now())
		}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.cfg.Probe[0], h.cfg.Probe[1:]...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		log.Printf("slurm: probe: %v: %s", err, strings.TrimSpace(out.String()))
		return
	}
	m := jobState.FindStringSubmatch(out.String())
	if m == nil {
		log.Printf("slurm: probe: no JobState in %q", strings.TrimSpace(out.String()))
		return
	}
	switch state := m[1]; state {
	case "RUNNING", "CONFIGURING", "PENDING", "SUSPENDED", "RESIZING":
		if !paused {
			h.health.MarkSync(time.Now())
		}
	default:
		// COMPLETING, COMPLETED, CANCELLED, FAILED, TIMEOUT, PREEMPTED,
		// NODE_FAIL, ...: the allocation is over while the agent lives.
		// Every fence is revoked, then the agent leaves with it.
		if h.lose(ctx, "job "+h.job.ID+" is "+state) {
			h.cfg.OnJobEnd()
		}
	}
}

// lose delivers a scope-loss reason once; reports whether it was new.
func (h *Home) lose(ctx context.Context, reason string) bool {
	h.mu.Lock()
	fn := h.scopeLost
	repeat := h.lost == reason
	h.lost = reason
	h.mu.Unlock()
	if repeat {
		return false
	}
	log.Printf("slurm: scope lost: %s", reason)
	if fn != nil {
		fn(ctx, reason)
	}
	return true
}

var _ home.Home = (*Home)(nil)
