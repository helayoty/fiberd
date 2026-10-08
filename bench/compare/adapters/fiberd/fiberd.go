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
package fiberd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	Framing  compare.Framing
	// WantScheme refuses an endpoint of another scheme. "tcp" gates the
	// gVisor row on kind on the agent's relay.
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
		FiberMax: a.o.FiberMax, WBudgetBytes: a.o.WBudget,
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
// f-<epoch>-<seq>, the template's is zygote. With no handles it is the
// zygote's charge, what stands between activations. A backend with no
// per-fiber leaf (Hyperlight's helper holds every sandbox) is charged
// as the subtree beyond the zygote.
func (a *Adapter) Density(_ context.Context, hs []compare.Handle) (int64, error) {
	if a.o.CgroupRoot == "" {
		return 0, compare.ErrUnsupported
	}
	grantDir := filepath.Join(a.o.CgroupRoot, a.uid)
	zygote, err := compare.CgroupMemory(filepath.Join(grantDir, "zygote"))
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 {
		return zygote, nil
	}
	var dirs []string
	for _, h := range hs {
		dirs = append(dirs, filepath.Join(grantDir, LeafName(h.Meta["fence"])))
	}
	if sum, err := compare.SumCgroups(dirs); err == nil {
		return sum, nil
	}
	total, err := compare.CgroupMemory(grantDir)
	if err != nil {
		return 0, err
	}
	return total - zygote, nil
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
