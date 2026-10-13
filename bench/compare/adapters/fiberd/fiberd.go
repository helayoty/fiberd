// Package fiberd is the fiberd comparator for every backend: one gRPC
// Clone, then the first request to the endpoint Clone returned. The
// grant is minted in-process from the issuer's key, as a consumer that
// holds one would present it. The adapter dials whatever Clone returns
// and knows nothing about the backend behind it, which is what makes the
// proc, runc, gVisor and Hyperlight rows comparable.
//
// Hyperlight fibers speak the line protocol only, so Framing picks what
// the probe sends. Proc is run under both framings in one run, so the
// framing gap is a measured delta and not an assumption.
//
// FiberWarm asks the home to keep that many restored sandboxes pooled
// for the grant. The adapter then refills untimed before every step and
// charges the idle pool to density's standing cost.
package fiberd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/bench/compare"
)

// Options configure the adapter.
type Options struct {
	// Target is the home's Fibers service, plaintext.
	Target string
	// IssuerKey is the private JWK the grant is minted with, and
	// IssuerURL the issuer the home verifies against.
	IssuerKey, IssuerURL string
	// NodeID is the grant's audience, the home's node id.
	NodeID string
	// TemplateDigest selects the home's -template mapping.
	TemplateDigest string
	// Tenant is what the grant's named sessions are filed under. Default
	// "compare".
	Tenant    string
	Isolation string
	// WBudget and FiberMax are the grant's limits. WBudget is the
	// per-instance memory limit of the fairness rule.
	WBudget  uint64
	FiberMax int
	// FiberWarm is the grant's fibers.warm, the sandboxes the home pools.
	FiberWarm int
	// RefillWait bounds one Refill. Default 2 minutes.
	RefillWait time.Duration
	Framing    compare.Framing
	// WantScheme refuses an endpoint of another scheme. "tcp" gates the
	// gVisor row on kind on fiberd's relay.
	WantScheme string
	// CgroupRoot is the home's cgroup root for density. Empty disables it.
	CgroupRoot string
	// Deadline is the Clone deadline.
	Deadline time.Duration
	Poll     time.Duration
	// Mint overrides minting, for tests. Nil mints from IssuerKey.
	Mint func() (string, error)
	// Client overrides the dialed client, for tests.
	Client *consumer.Client
}

// Adapter implements compare.Adapter.
type Adapter struct {
	o      Options
	client *consumer.Client
	token  string
	uid    string
}

// New mints the grant and dials the home.
func New(ctx context.Context, o Options) (*Adapter, error) {
	if o.Target == "" && o.Client == nil {
		return nil, errors.New("fiberd: need Target")
	}
	if o.Deadline <= 0 {
		o.Deadline = 30 * time.Second
	}
	if o.Framing == "" {
		o.Framing = compare.HTTP
	}
	if o.RefillWait <= 0 {
		o.RefillWait = 2 * time.Minute
	}
	a := &Adapter{o: o, client: o.Client}
	a.uid = fmt.Sprintf("compare-%d", time.Now().UnixNano())
	mint := o.Mint
	if mint == nil {
		mint = a.mint
	}
	tok, err := mint()
	if err != nil {
		return nil, fmt.Errorf("fiberd: mint: %w", err)
	}
	a.token = tok
	if a.client == nil {
		a.client, err = consumer.Dial(ctx, o.Target)
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

// Grant is the grant the adapter presents.
func (a *Adapter) Grant() (core.Grant, error) {
	iso, err := core.ParseIsolation(a.o.Isolation)
	if err != nil {
		return core.Grant{}, err
	}
	digest := a.o.TemplateDigest
	if digest == "" {
		digest = "sha256:compare"
	}
	tenant := a.o.Tenant
	if tenant == "" {
		tenant = "compare"
	}
	return core.Grant{
		UID: a.uid, Audience: a.o.NodeID, TemplateDigest: digest, Tenant: tenant,
		FiberMax: a.o.FiberMax, FiberWarm: a.o.FiberWarm, WBudgetBytes: a.o.WBudget,
		LeaseExpiry: time.Now().Add(time.Hour).Truncate(time.Second),
		Policy:      core.Policy{Isolation: iso},
	}, nil
}

func (a *Adapter) mint() (string, error) {
	if a.o.IssuerKey == "" || a.o.IssuerURL == "" || a.o.NodeID == "" {
		return "", errors.New("need IssuerKey, IssuerURL and NodeID")
	}
	key, err := grant.LoadKey(a.o.IssuerKey)
	if err != nil {
		return "", err
	}
	g, err := a.Grant()
	if err != nil {
		return "", err
	}
	return (&grant.Issuer{Key: key, URL: a.o.IssuerURL}).Mint(g)
}

// Close drops the connection.
func (a *Adapter) Close() error { return a.client.Close() }

// Setup is one Clone and Release. The first Clone admits the grant,
// warms the template and fetches the JWKS, which is paid once per grant
// and reported as setup.
func (a *Adapter) Setup(ctx context.Context) error {
	h, err := a.Activate(ctx, "setup")
	if err != nil {
		return err
	}
	if _, _, err := a.Ready(ctx, h); err != nil {
		_ = a.Release(ctx, h)
		return err
	}
	return a.Release(ctx, h)
}

// Refill waits until Watch reports the grant's pool full, so every step
// starts from one. Without fibers.warm there is nothing to wait for.
func (a *Adapter) Refill(ctx context.Context) error {
	if a.o.FiberWarm <= 0 {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, a.o.RefillWait)
	defer cancel()
	var pooled uint32
	full := false
	err := a.client.Watch(wctx, func(s consumer.Status) {
		if s.GrantUID != a.uid {
			return
		}
		pooled = s.Pooled
		if int(pooled) >= a.o.FiberWarm {
			full = true
			cancel()
		}
	})
	if full {
		return nil
	}
	if err == nil {
		err = wctx.Err()
	}
	return fmt.Errorf("fiberd: grant %s has %d of %d pooled: %w", a.uid, pooled, a.o.FiberWarm, err)
}

// Activate is Clone. The session is named after id so Park and a later
// Clone of the same name resume it. The endpoint is the address.
func (a *Adapter) Activate(ctx context.Context, id string) (compare.Handle, error) {
	f, err := a.client.Clone(ctx, a.token, "s-"+id, a.o.Deadline, nil)
	if err != nil {
		return compare.Handle{}, err
	}
	return a.handle(f, id)
}

func (a *Adapter) handle(f consumer.Fiber, id string) (compare.Handle, error) {
	ep, err := endpoint.Parse(f.Endpoint)
	if err != nil {
		return compare.Handle{}, err
	}
	if a.o.WantScheme != "" && ep.Scheme != a.o.WantScheme {
		return compare.Handle{}, fmt.Errorf("fiberd: endpoint %s has scheme %s, want %s (relay not in place)", f.Endpoint, ep.Scheme, a.o.WantScheme)
	}
	return compare.Handle{ID: f.ID, Addr: f.Endpoint, Meta: map[string]string{
		"session": "s-" + id, "fence": f.Fence.String(), "kind": f.Kind.String(),
	}}, nil
}

// Ready sends the first request. fiberd returns an endpoint that
// already listens, so the first request is the measurement and
// Attempts is expected to stay 0.
func (a *Adapter) Ready(ctx context.Context, h compare.Handle) (compare.Handle, time.Time, error) {
	dial := func(ctx context.Context) (net.Conn, error) { return endpoint.Dial(ctx, h.Addr) }
	r, err := compare.Probe{Dial: dial, Framing: a.o.Framing, Poll: a.o.Poll}.Run(ctx)
	if err != nil {
		return h, time.Time{}, err
	}
	h.Meta["attempts"] = strconv.Itoa(r.Attempts)
	return h, r.FirstByte, nil
}

// Release ends the fiber and discards its session's state.
func (a *Adapter) Release(ctx context.Context, h compare.Handle) error {
	err := a.client.Release(ctx, h.ID, true)
	if consumer.NotFound(err) {
		return nil
	}
	return err
}

// Park parks the fiber synchronously, keeping its session's state.
func (a *Adapter) Park(ctx context.Context, h compare.Handle) error {
	return a.client.Park(ctx, h.ID, true)
}

// Resume clones the parked fiber's session again, which the home serves
// as RESUME.
func (a *Adapter) Resume(ctx context.Context, h compare.Handle) (compare.Handle, error) {
	f, err := a.client.Clone(ctx, a.token, h.Meta["session"], a.o.Deadline, nil)
	if err != nil {
		return compare.Handle{}, fmt.Errorf("clone after park: %w", err)
	}
	if f.Kind != consumer.Resume {
		_ = a.client.Release(ctx, f.ID, true)
		return compare.Handle{}, fmt.Errorf("clone after park is %s, want RESUME", f.Kind)
	}
	return a.handle(f, strings.TrimPrefix(h.Meta["session"], "s-"))
}

// Density reads the grant's cgroup subtree. The fibers' leaves are
// f-<epoch>-<seq>, the template's is zygote, and pooled sandboxes are
// pool/p-<n>, which a fiber handed one keeps. With no handles it is
// what stands between activations, the zygote and a full pool. A
// backend with no per-fiber leaf (Hyperlight's helper holds every
// sandbox) is charged as the subtree beyond the zygote.
func (a *Adapter) Density(ctx context.Context, hs []compare.Handle) (int64, error) {
	if a.o.CgroupRoot == "" {
		return 0, compare.ErrUnsupported
	}
	grantDir := filepath.Join(a.o.CgroupRoot, a.uid)
	zygote, err := compare.CgroupMemory(filepath.Join(grantDir, "zygote"))
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 && a.o.FiberWarm <= 0 {
		return zygote, nil
	}
	if len(hs) == 0 {
		if err := a.Refill(ctx); err != nil {
			return 0, err
		}
	}
	pool, err := PoolLeaves(grantDir)
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 {
		// The home hands out its oldest pooled sandbox and fills one at a
		// time, so the newest leaves are the idle ones.
		idle, err := compare.SumCgroups(pool[max(len(pool)-a.o.FiberWarm, 0):])
		return zygote + idle, err
	}
	var dirs []string
	handed := 0
	for _, h := range hs {
		d := filepath.Join(grantDir, LeafName(h.Meta["fence"]))
		if _, err := os.Stat(d); err != nil {
			handed++
			continue
		}
		dirs = append(dirs, d)
	}
	if handed <= len(pool) {
		if sum, err := compare.SumCgroups(append(dirs, pool[:handed]...)); err == nil {
			return sum, nil
		}
	}
	total, err := compare.CgroupMemory(grantDir)
	if err != nil {
		return 0, err
	}
	return total - zygote, nil
}

// PoolLeaves lists the grant's pool leaves oldest first, none when it
// has no pool.
func PoolLeaves(grantDir string) ([]string, error) {
	es, err := os.ReadDir(filepath.Join(grantDir, "pool"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type leaf struct {
		n   int
		dir string
	}
	var ls []leaf
	for _, e := range es {
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "p-"))
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "p-") || err != nil {
			continue
		}
		ls = append(ls, leaf{n, filepath.Join(grantDir, "pool", e.Name())})
	}
	slices.SortFunc(ls, func(x, y leaf) int { return x.n - y.n })
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.dir
	}
	return out, nil
}

// LeafName is the fiber leaf for a fence "grant/epoch/seq", as
// pkg/runtime/host names it.
func LeafName(fence string) string {
	p := strings.Split(fence, "/")
	if len(p) != 3 {
		return fence
	}
	return "f-" + p[1] + "-" + p[2]
}

// Exists reports whether the cgroup root is usable, for the scripts.
func Exists(root string) bool {
	_, err := os.Stat(root)
	return err == nil
}
