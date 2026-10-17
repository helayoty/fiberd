package core_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// deadlineRuntime records the spec of the last clone it was asked for.
type deadlineRuntime struct {
	fakeRuntime
	spec *core.CloneSpec
}

func (r deadlineRuntime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	*r.spec = spec
	return r.fakeRuntime.Clone(ctx, spec)
}

// advisedRuntime is a deadlineRuntime that advises its own defaults for
// one grant, like a runtime whose create is slower than a fork and sized
// from what it measured when that grant's template warmed. Any other
// grant gets no advice.
type advisedRuntime struct {
	deadlineRuntime
	grant          string
	create, resume time.Duration
}

func (r advisedRuntime) DefaultDeadlines(uid string) (time.Duration, time.Duration) {
	if uid != r.grant {
		return 0, 0
	}
	return r.create, r.resume
}

// TestGrantDeadlines checks the one source of a grant's deadlines: the
// runtime's advice for that grant when it advises both, else the
// defaults. A runtime that advises nothing, or for another grant, or
// only one of the two, leaves the defaults.
func TestGrantDeadlines(t *testing.T) {
	cases := []struct {
		name           string
		advise         string // the grant the runtime advises for, "" for a runtime that advises nothing
		create, resume time.Duration
		grant          string
		wantC, wantR   time.Duration
	}{
		{name: "a runtime that advises nothing", grant: "g1", wantC: core.DefaultCreateDeadline, wantR: core.DefaultResumeDeadline},
		{name: "advice for the grant", advise: "g1", create: 5 * time.Second, resume: 9 * time.Second, grant: "g1", wantC: 5 * time.Second, wantR: 9 * time.Second},
		{name: "advice for another grant", advise: "g2", create: 5 * time.Second, resume: 9 * time.Second, grant: "g1", wantC: core.DefaultCreateDeadline, wantR: core.DefaultResumeDeadline},
		{name: "advice with a zero resume is ignored", advise: "g1", create: 5 * time.Second, grant: "g1", wantC: core.DefaultCreateDeadline, wantR: core.DefaultResumeDeadline},
		{name: "advice with a zero create is ignored", advise: "g1", resume: 9 * time.Second, grant: "g1", wantC: core.DefaultCreateDeadline, wantR: core.DefaultResumeDeadline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rt core.Runtime = deadlineRuntime{}
			if tc.advise != "" {
				rt = advisedRuntime{grant: tc.advise, create: tc.create, resume: tc.resume}
			}
			c, r := core.GrantDeadlines(rt, tc.grant)
			if c != tc.wantC || r != tc.wantR {
				t.Fatalf("GrantDeadlines = %s/%s, want %s/%s", c, r, tc.wantC, tc.wantR)
			}
		})
	}
}

// TestCloneDefaultDeadlines checks the deadline the runtime is given. The
// caller's own deadline is always honoured. Without one, a create gets the
// create default and a resume the resume default, from the runtime when
// it advises both for the clone's grant, else from the core.
func TestCloneDefaultDeadlines(t *testing.T) {
	cases := []struct {
		name     string
		deadline time.Duration // the request's
		advise   string        // the grant the runtime advises for, "" for none
		create   time.Duration // advised
		resume   time.Duration // advised
		resumeS  bool          // the session is parked, so the clone resumes it
		want     time.Duration
	}{
		{name: "the caller's deadline is honoured over advice", deadline: 300 * time.Millisecond, advise: "g1", create: 5 * time.Second, resume: 9 * time.Second,
			want: 300 * time.Millisecond},
		{name: "a create without a deadline gets the core default", want: core.DefaultCreateDeadline},
		{name: "a resume without a deadline gets the core default", resumeS: true, want: core.DefaultResumeDeadline},
		{name: "a create without a deadline gets the runtime's advice for its grant", advise: "g1", create: 5 * time.Second, resume: 9 * time.Second,
			want: 5 * time.Second},
		{name: "a resume without a deadline gets the runtime's advice for its grant", advise: "g1", create: 5 * time.Second, resume: 9 * time.Second,
			resumeS: true, want: 9 * time.Second},
		{name: "advice for another grant is not this grant's", advise: "g2", create: 5 * time.Second, resume: 9 * time.Second,
			want: core.DefaultCreateDeadline},
		{name: "advice with a zero create is ignored", advise: "g1", resume: 9 * time.Second, want: core.DefaultCreateDeadline},
		{name: "advice with a zero resume is ignored", advise: "g1", create: 5 * time.Second, resumeS: true, want: core.DefaultResumeDeadline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 2}
			a := newCore(t, "up", core.TierCheckpoint, g)
			var spec core.CloneSpec
			dr := deadlineRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)}, spec: &spec}
			a.Runtime = dr
			if tc.advise != "" {
				a.Runtime = advisedRuntime{deadlineRuntime: dr, grant: tc.advise, create: tc.create, resume: tc.resume}
			}
			wantSource, wantRef := core.SourceZygote, ""
			if tc.resumeS {
				a.Ledger.AdmitGrant(g)
				createFiber(t, a.Ledger, "g1", "S", "f1")
				a.Ledger.OnPark("f1", "delta-f1")
				wantSource, wantRef = core.SourceDelta, "delta-f1"
			}
			r, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: tc.deadline})
			if err != nil || code != core.OK {
				t.Fatalf("clone = %d %v, want OK", code, err)
			}
			if spec.Deadline != tc.want {
				t.Fatalf("runtime deadline = %s, want %s", spec.Deadline, tc.want)
			}
			if spec.Source != wantSource || spec.Ref != wantRef || spec.Fence != r.Fence {
				t.Fatalf("spec = source %d ref %q fence %s, want source %d ref %q fence %s", spec.Source, spec.Ref, spec.Fence, wantSource, wantRef, r.Fence)
			}
		})
	}
}

// prepRuntime is a fakeRuntime whose PrepareTemplate announces itself,
// waits for the test, and then answers the next error queued in errs, or
// nil once the queue is empty.
type prepRuntime struct {
	fakeRuntime
	started chan struct{}
	proceed chan struct{}
	errs    chan error
}

func (r prepRuntime) PrepareTemplate(context.Context, core.Grant) error {
	r.started <- struct{}{}
	<-r.proceed
	select {
	case err := <-r.errs:
		return err
	default:
		return nil
	}
}

// waitCtx closes waiting the first time Done is asked for. Admit asks only
// in its wait for an admission in flight, so the test knows when a second
// Admit has reached it.
type waitCtx struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// TestAdmitWaitsForInflight admits a grant twice at once. The second
// waits for the first instead of warming the template again, and shares
// what the first admitted. It admits itself when the first failed, or
// when it carries a longer lease than the first admitted, so neither a
// retry nor a renewal is lost. A second whose context ends stops waiting.
func TestAdmitWaitsForInflight(t *testing.T) {
	lease := time.Now().Add(time.Hour)
	cases := []struct {
		name         string
		firstErr     error         // what the first admission's template warm answers
		secondLease  time.Duration // the second grant's lease, relative to the first's; 0 is the same
		cancelSecond bool
		wantFirst    core.StatusCode
		wantSecond   core.StatusCode
		wantErr      error // the second's
		wantAdmitted bool
		wantWarms    int           // template warms in all
		wantLease    time.Duration // the admitted lease, relative to the first's
	}{
		{name: "the second shares the first's success", wantFirst: core.OK, wantSecond: core.OK, wantAdmitted: true, wantWarms: 1},
		{name: "the second retries after the first's failure", firstErr: errors.New("pull: manifest unknown"),
			wantFirst: core.DeferredFallback, wantSecond: core.OK, wantAdmitted: true, wantWarms: 2},
		{name: "a second whose context ends stops waiting", cancelSecond: true,
			wantFirst: core.OK, wantSecond: core.DeferredFallback, wantErr: context.Canceled, wantAdmitted: true, wantWarms: 1},
		{name: "a second with a longer lease admits its renewal after the first", secondLease: time.Hour,
			wantFirst: core.OK, wantSecond: core.OK, wantAdmitted: true, wantWarms: 2, wantLease: time.Hour},
		{name: "a second with a shorter lease shares the first's success", secondLease: -30 * time.Minute,
			wantFirst: core.OK, wantSecond: core.OK, wantAdmitted: true, wantWarms: 1},
	}
	type result struct {
		code core.StatusCode
		err  error
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", LeaseExpiry: lease}
			a := newCore(t, "up", core.TierCheckpoint)
			rt := prepRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, started: make(chan struct{}, 2), proceed: make(chan struct{}), errs: make(chan error, 1)}
			if tc.firstErr != nil {
				rt.errs <- tc.firstErr
			}
			a.Runtime = rt
			first := make(chan result, 1)
			go func() {
				code, err := a.Admit(context.Background(), g)
				first <- result{code, err}
			}()
			select {
			case <-rt.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the first admission never warmed the template")
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelSecond {
				cancel()
			}
			ctx := &waitCtx{Context: base, waiting: make(chan struct{})}
			g2 := g
			g2.LeaseExpiry = lease.Add(tc.secondLease)
			second := make(chan result, 1)
			go func() {
				code, err := a.Admit(ctx, g2)
				second <- result{code, err}
			}()
			select {
			case <-ctx.waiting:
			case <-time.After(5 * time.Second):
				t.Fatal("the second admission never waited for the first")
			}
			if tc.cancelSecond {
				// It returns while the first is still in flight.
				r := <-second
				second <- r
			}
			close(rt.proceed)
			r1, r2 := <-first, <-second
			if r1.code != tc.wantFirst {
				t.Fatalf("first admit = %d %v, want %d", r1.code, r1.err, tc.wantFirst)
			}
			if r2.code != tc.wantSecond || !errors.Is(r2.err, tc.wantErr) {
				t.Fatalf("second admit = %d %v, want %d %v", r2.code, r2.err, tc.wantSecond, tc.wantErr)
			}
			// The first warm was taken above, so the rest are the retries.
			if n := 1 + len(rt.started); n != tc.wantWarms {
				t.Fatalf("the template was warmed %d times, want %d", n, tc.wantWarms)
			}
			held, ok := a.Ledger.Grant("g1")
			if ok != tc.wantAdmitted {
				t.Fatalf("admitted = %v, want %v", ok, tc.wantAdmitted)
			}
			if ok && !held.LeaseExpiry.Equal(lease.Add(tc.wantLease)) {
				t.Fatalf("admitted lease = %s, want %s", held.LeaseExpiry.Sub(lease), tc.wantLease)
			}
		})
	}
}

// TestAdmitRefreshKeepsDevices re-delivers an admitted grant that holds a
// device channel. A refresh that fails gives back only the channel it
// provisioned, hands the old one back to the runtime, and leaves it for
// the revoke to release. A refresh that succeeds replaces the channel.
func TestAdmitRefreshKeepsDevices(t *testing.T) {
	gpu := core.DeviceBudget{Bytes: 1 << 30, Class: "gpu"}
	cases := []struct {
		name          string
		plain         bool // the runtime takes no device channel
		prepErr       error
		devicesErr    error
		device        core.DeviceBudget
		offers        map[string]bool // the refresh's, the first delivery offers every class
		want          core.StatusCode
		wantErr       error
		wantAttached  []string // the channels the runtime was handed, in order
		wantReleased  []string // the channels given back by the refresh
		wantAfterDrop []string // the channels given back once the grant is revoked
	}{
		{name: "a refresh that succeeds replaces the channel",
			want: core.OK, wantAttached: []string{"c1", "c2"}, wantReleased: []string{"c1"}, wantAfterDrop: []string{"c1", "c2"}},
		{name: "a refresh whose template fails to warm keeps the old channel", prepErr: errors.New("pull: manifest unknown"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, wantAttached: []string{"c1", "c2", "c1"}, wantReleased: []string{"c2"}, wantAfterDrop: []string{"c2", "c1"}},
		{name: "a refresh whose device class is no longer offered keeps the old channel", device: gpu, offers: map[string]bool{"sim": true},
			want: core.NeedsTier, wantErr: core.ErrNeedsDevice, wantAttached: []string{"c1", "c2", "c1"}, wantReleased: []string{"c2"}, wantAfterDrop: []string{"c2", "c1"}},
		{name: "a refresh whose channel cannot be provisioned keeps the old channel", devicesErr: errors.New("claim pending"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, wantAttached: []string{"c1"}, wantAfterDrop: []string{"c1"}},
		{name: "a failed refresh on a runtime that takes no channel keeps the old one", plain: true, prepErr: errors.New("pull: manifest unknown"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, wantReleased: []string{"c2"}, wantAfterDrop: []string{"c2", "c1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", DeviceBudget: tc.device}
			a := newCore(t, "up", core.TierCheckpoint)
			rt := &admitRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, offers: map[string]bool{"gpu": true, "sim": true}}
			if tc.plain {
				a.Runtime = plainPrepRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, rt: rt}
			} else {
				a.Runtime = rt
			}
			var provisioned int
			var released []string
			var devicesErr error
			a.Devices = func(context.Context, core.Grant) (core.DeviceChannel, func(), error) {
				if devicesErr != nil {
					return core.DeviceChannel{}, nil, devicesErr
				}
				provisioned++
				name := fmt.Sprintf("c%d", provisioned)
				return core.DeviceChannel{Kind: "static", Detail: name}, func() { released = append(released, name) }, nil
			}
			if code, err := a.Admit(context.Background(), g); err != nil || code != core.OK {
				t.Fatalf("first admit = %d %v, want OK", code, err)
			}
			rt.prepErr, devicesErr = tc.prepErr, tc.devicesErr
			if tc.offers != nil {
				rt.offers = tc.offers
			}
			code, err := a.Admit(context.Background(), g)
			if code != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("refresh = %d %v, want %d %v", code, err, tc.want, tc.wantErr)
			}
			var attached []string
			for _, fc := range rt.attached {
				attached = append(attached, fc.Detail)
			}
			if !slices.Equal(attached, tc.wantAttached) || !slices.Equal(released, tc.wantReleased) {
				t.Fatalf("attached %v released %v, want %v %v", attached, released, tc.wantAttached, tc.wantReleased)
			}
			if _, ok := a.Ledger.Grant("g1"); !ok {
				t.Fatal("the grant left the ledger")
			}
			a.Revoke("g1")
			if !slices.Equal(released, tc.wantAfterDrop) {
				t.Fatalf("released after revoke %v, want %v", released, tc.wantAfterDrop)
			}
		})
	}
}

// plainPrepRuntime warms templates like rt but takes no device channel
// and offers no device.
type plainPrepRuntime struct {
	fakeRuntime
	rt *admitRuntime
}

func (r plainPrepRuntime) PrepareTemplate(ctx context.Context, g core.Grant) error {
	return r.rt.PrepareTemplate(ctx, g)
}

// durableLog records each audit record with the durability it was asked
// for.
type durableLog struct {
	mu   sync.Mutex
	durs map[string]core.Durability // event -> durability of its last record
}

func (r *durableLog) Append(_ context.Context, d core.Durability, rec core.AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.durs == nil {
		r.durs = map[string]core.Durability{}
	}
	r.durs[rec.Event] = d
	return nil
}

// TestCloneUnderAdmittedGrant presents a token whose budgets differ from
// the grant the home admitted under the same UID. The fiber runs under
// the admitted W and device budgets and the admitted durability, so a
// budget the home lowered since the token was minted is enforced. A grant
// the home never delivered is admitted from the token and runs under it.
func TestCloneUnderAdmittedGrant(t *testing.T) {
	cases := []struct {
		name       string
		admitted   *core.Grant // nil means the home never delivered the grant
		wantW      uint64
		wantDevice uint64
		wantDur    core.Durability
	}{
		{name: "the admitted W budget is enforced over the token's", admitted: &core.Grant{WBudgetBytes: 100},
			wantW: 100, wantDur: core.BestEffort},
		{name: "the admitted device budget is enforced over the token's", admitted: &core.Grant{DeviceBudget: core.DeviceBudget{Bytes: 1 << 20}},
			wantDevice: 1 << 20, wantDur: core.BestEffort},
		{name: "the admitted durability is enforced over the token's", admitted: &core.Grant{Policy: core.Policy{Durability: core.Sync}},
			wantDur: core.Sync},
		{name: "a grant the home never delivered runs under the token",
			wantW: 1000, wantDur: core.BestEffort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", WBudgetBytes: 1000, Policy: core.Policy{Durability: core.BestEffort}}
			if tc.admitted != nil {
				// Only an admitted grant passes a device budget here, since
				// the runtime offers no device for a self-admission.
				token.DeviceBudget = core.DeviceBudget{Bytes: 1 << 30}
			}
			a := newCore(t, "up", core.TierCheckpoint, token)
			var spec core.CloneSpec
			a.Runtime = deadlineRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)}, spec: &spec}
			rec := &durableLog{}
			a.Audit = rec
			if tc.admitted != nil {
				g := *tc.admitted
				g.UID, g.Tenant, g.Audience = token.UID, token.Tenant, token.Audience
				a.Ledger.AdmitGrant(g)
			}
			if _, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
				t.Fatalf("clone = %d %v, want OK", code, err)
			}
			if got := rec.durs["create"]; got != tc.wantDur {
				t.Fatalf("create record durability = %d, want %d", got, tc.wantDur)
			}
			if spec.Grant.WBudgetBytes != tc.wantW || spec.Grant.DeviceBudget.Bytes != tc.wantDevice {
				t.Fatalf("runtime got w_budget %d device_budget %d, want %d %d", spec.Grant.WBudgetBytes, spec.Grant.DeviceBudget.Bytes, tc.wantW, tc.wantDevice)
			}
		})
	}
}

// admitRuntime warms templates with prepErr, offers the device classes in
// offers, and records the device channels it is given.
type admitRuntime struct {
	fakeRuntime
	prepErr  error
	offers   map[string]bool
	attached []core.DeviceChannel
}

func (r *admitRuntime) PrepareTemplate(context.Context, core.Grant) error { return r.prepErr }
func (r *admitRuntime) OffersDevice(_, class string) bool                 { return r.offers[class] }
func (r *admitRuntime) AttachDevices(_ string, fc core.DeviceChannel) {
	r.attached = append(r.attached, fc)
}

// TestAdmitOutcomes checks what Admit answers and what becomes of the
// grant's device channel. A grant refused after provisioning gives its
// channel back, a re-delivery releases the channel it replaces, and a
// device budget is admitted only where the template offers the class.
func TestAdmitOutcomes(t *testing.T) {
	gpu := core.DeviceBudget{Bytes: 1 << 30, Class: "gpu"}
	cases := []struct {
		name         string
		health       string
		plain        bool // the runtime takes no device channel and offers no device
		devicesErr   error
		prepErr      error
		offers       map[string]bool
		device       core.DeviceBudget
		admits       int // how many times the grant is delivered, 0 means once
		want         core.StatusCode
		wantErr      error
		wantAdmitted bool
		provisioned  int
		released     int
		attached     int
	}{
		{name: "a device channel is provisioned and attached to a runtime that takes one",
			want: core.OK, wantAdmitted: true, provisioned: 1, attached: 1},
		{name: "a device channel on a runtime that takes none is provisioned only", plain: true,
			want: core.OK, wantAdmitted: true, provisioned: 1},
		{name: "a device channel that cannot be provisioned is not ready", devicesErr: errors.New("claim pending"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, provisioned: 1},
		{name: "a device channel that cannot be provisioned with the issuer unreachable is shed", health: "down", devicesErr: errors.New("claim pending"),
			want: core.Shed, wantErr: core.ErrNotReady, provisioned: 1},
		{name: "a template that fails to warm releases the device channel", prepErr: errors.New("pull: manifest unknown"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, provisioned: 1, released: 1, attached: 1},
		{name: "a re-delivery releases the device channel it replaces", admits: 2,
			want: core.OK, wantAdmitted: true, provisioned: 2, released: 1, attached: 2},
		{name: "a device class the template offers is admitted", device: gpu, offers: map[string]bool{"gpu": true},
			want: core.OK, wantAdmitted: true, provisioned: 1, attached: 1},
		{name: "a device class the template does not offer is needs-tier, and the device channel is released", device: gpu, offers: map[string]bool{"sim": true},
			want: core.NeedsTier, wantErr: core.ErrNeedsDevice, provisioned: 1, released: 1, attached: 1},
		{name: "a device budget on a runtime with no device is needs-tier, and the device channel is released", plain: true, device: gpu,
			want: core.NeedsTier, wantErr: core.ErrNeedsDevice, provisioned: 1, released: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			health := tc.health
			if health == "" {
				health = "up"
			}
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", DeviceBudget: tc.device}
			a := newCore(t, health, core.TierCheckpoint)
			rt := &admitRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, prepErr: tc.prepErr, offers: tc.offers}
			if tc.plain {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint}
			} else {
				a.Runtime = rt
			}
			var provisioned, released int
			a.Devices = func(context.Context, core.Grant) (core.DeviceChannel, func(), error) {
				provisioned++
				if tc.devicesErr != nil {
					return core.DeviceChannel{}, nil, tc.devicesErr
				}
				return core.DeviceChannel{Kind: "static", Devices: []string{"/dev/sim0"}}, func() { released++ }, nil
			}
			var (
				code core.StatusCode
				err  error
			)
			for range max(tc.admits, 1) {
				code, err = a.Admit(context.Background(), g)
			}
			if code != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("admit = %d %v, want %d %v", code, err, tc.want, tc.wantErr)
			}
			if _, ok := a.Ledger.Grant("g1"); ok != tc.wantAdmitted {
				t.Fatalf("admitted = %v, want %v", ok, tc.wantAdmitted)
			}
			if provisioned != tc.provisioned || released != tc.released || len(rt.attached) != tc.attached {
				t.Fatalf("device channel provisioned=%d released=%d attached=%d, want %d %d %d",
					provisioned, released, len(rt.attached), tc.provisioned, tc.released, tc.attached)
			}
			// Revoking an admitted grant gives its one channel back.
			// Revoking a refused one finds nothing left to release.
			a.Revoke("g1")
			wantReleased := tc.released
			if tc.wantAdmitted {
				wantReleased++
			}
			if released != wantReleased {
				t.Fatalf("released after revoke = %d, want %d", released, wantReleased)
			}
		})
	}
}

// TestYield checks that Yield revokes the grant and releases every running
// fiber under it, with a yield record for each and one revoke record. A
// fiber the runtime cannot release leaves the ledger all the same, since
// the grant that counted it is gone. A fiber that exits on its own while
// Yield works is recorded as its exit, not released again. The warm
// template is dropped last, and a valid token re-admits the grant.
func TestYield(t *testing.T) {
	cases := []struct {
		name       string
		sessions   []string
		releaseErr error
		exitDuring bool // the second fiber exits while the first is released
		wantYields int
	}{
		{name: "every running fiber is released", sessions: []string{"S", ""}, wantYields: 2},
		{name: "a release the runtime refuses still drops the fiber", sessions: []string{"S", ""}, releaseErr: errors.New("kill: EPERM"), wantYields: 2},
		{name: "a grant with nothing running is revoked", sessions: nil},
		{name: "a fiber that exits during the yield is not released again", sessions: []string{"S", ""}, exitDuring: true, wantYields: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 4}
			a := newCore(t, "up", core.TierCheckpoint, g)
			rt := &listingRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, releaseErr: tc.releaseErr}
			a.Runtime = rt
			rec := &auditLog{}
			a.Audit = rec
			ctx := context.Background()
			var fibers []string
			for _, s := range tc.sessions {
				r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: s, Deadline: time.Second})
				if err != nil || code != core.OK {
					t.Fatalf("clone %q = %d %v", s, code, err)
				}
				fibers = append(fibers, r.FiberID)
			}
			if tc.exitDuring {
				rt.onRelease = func(id string) {
					if id == fibers[0] {
						a.OnExit(ctx, core.FiberExit{FiberID: fibers[1], Reason: "exit"})
					}
				}
			}
			a.Yield(ctx, "g1", "ladder")
			if _, ok := a.Ledger.Grant("g1"); ok {
				t.Fatal("grant still admitted after yield")
			}
			if ids := a.Ledger.RunningFibers(); len(ids) != 0 {
				t.Fatalf("running fibers after yield = %v, want none", ids)
			}
			if len(rt.released) != tc.wantYields {
				t.Fatalf("released %v, want %d of %v", rt.released, tc.wantYields, fibers)
			}
			yields := rec.events("yield")
			if len(yields) != tc.wantYields {
				t.Fatalf("yield records = %+v, want %d", yields, tc.wantYields)
			}
			if exits := rec.events("exit"); (len(exits) == 1) != tc.exitDuring {
				t.Fatalf("exit records = %+v, want one %v", exits, tc.exitDuring)
			}
			for _, y := range yields {
				if y.Detail != "ladder" || y.Fence.GrantUID != "g1" {
					t.Fatalf("yield record = %+v, want the reason and the grant's fence", y)
				}
			}
			if rv := rec.events("revoke"); len(rv) != 1 || rv[0].Detail != "ladder" {
				t.Fatalf("revoke records = %+v, want one with the reason", rv)
			}
			if _, ok := coretest.GrantStatus(a.Ledger, "g1"); ok {
				t.Fatal("a status is still published for the yielded grant")
			}
			if len(rt.dropped) != 1 || rt.dropped[0] != "g1" {
				t.Fatalf("templates dropped = %v, want the yielded grant's", rt.dropped)
			}
			if r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK || r.Kind != core.ActCreate {
				t.Fatalf("clone after the yield = %v %d %v, want a fresh create under the re-admitted grant", r.Kind, code, err)
			}
		})
	}
}

// TestRemoveWaitsForAdmit removes a grant while its admission is warming
// the template. Remove waits for that admission and yields what it
// admitted, so the grant ends up denied and unknown, and a Clone with its
// token is refused. Before the fix Admit checked the deny-list before it
// registered itself, so a Remove between that check and the warm-up had
// nothing to wait for or yield, and the admission then landed a grant
// that was denied on paper and admitted in fact.
func TestRemoveWaitsForAdmit(t *testing.T) {
	cases := []struct {
		name     string
		inflight bool // the admission is warming when Remove runs
	}{
		{name: "remove during the warm-up waits for it and yields the grant", inflight: true},
		{name: "remove of an admitted grant yields it", inflight: false},
	}
	type result struct {
		code core.StatusCode
		err  error
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", LeaseExpiry: time.Now().Add(time.Hour)}
			a := newCore(t, "up", core.TierCheckpoint, g)
			rt := prepRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, started: make(chan struct{}, 2), proceed: make(chan struct{})}
			a.Runtime = rt
			rv, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			a.Revoked = rv
			ctx := context.Background()
			admitted := make(chan result, 1)
			go func() {
				code, err := a.Admit(ctx, g)
				admitted <- result{code, err}
			}()
			select {
			case <-rt.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the admission never warmed the template")
			}
			if !tc.inflight {
				close(rt.proceed)
				if r := <-admitted; r.code != core.OK {
					t.Fatalf("admit = %d %v, want OK", r.code, r.err)
				}
			}
			removed := make(chan struct{})
			go func() {
				defer close(removed)
				a.Remove(ctx, "g1")
			}()
			if tc.inflight {
				select {
				case <-removed:
					t.Fatal("Remove returned while the admission was still warming")
				case <-time.After(100 * time.Millisecond):
				}
				close(rt.proceed)
				// The admission passed its deny check before the removal, so
				// it lands, and the removal yields what it landed.
				if r := <-admitted; r.code != core.OK {
					t.Fatalf("admit = %d %v, want OK", r.code, r.err)
				}
			}
			<-removed
			if !rv.Denied("g1", g.LeaseExpiry, time.Now()) {
				t.Fatal("the removed grant is not denied")
			}
			if _, ok := a.Ledger.Grant("g1"); ok {
				t.Fatal("the removed grant is still admitted")
			}
			a.Runtime = fakeRuntime{tier: core.TierCheckpoint}
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second})
			if code == core.OK || !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("clone under the removed grant = %s %d %v, want refused as revoked", r.FiberID, code, err)
			}
		})
	}
}

// TestRedeliver checks that the home delivering a grant again lifts its
// denial and records it. With no deny-list, or no entry, there is nothing
// to lift and nothing is recorded. A lift that cannot be persisted still
// holds in memory.
func TestRedeliver(t *testing.T) {
	cases := []struct {
		name       string
		noList     bool
		remove     bool // the home removed the grant first
		unwritable bool // the deny-list's directory is gone before the lift
		wantRecord bool
	}{
		{name: "without a deny-list there is nothing to lift", noList: true},
		{name: "a grant never removed is not recorded", remove: false},
		{name: "a removed grant is lifted and recorded", remove: true, wantRecord: true},
		{name: "a lift that cannot be persisted still lifts", remove: true, unwritable: true, wantRecord: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a"}
			a := newCore(t, "up", core.TierCheckpoint, g)
			rec := &auditLog{}
			a.Audit = rec
			ctx := context.Background()
			dir := filepath.Join(t.TempDir(), "state")
			if !tc.noList {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				r, err := core.OpenRevoked(filepath.Join(dir, "revoked.json"), time.Hour, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				a.Revoked = r
			}
			if tc.remove {
				a.Remove(ctx, "g1")
			}
			if tc.unwritable {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			}
			a.Redeliver(ctx, "g1")
			if got := len(rec.events("redeliver")) == 1; got != tc.wantRecord {
				t.Fatalf("redeliver recorded = %v, want %v", got, tc.wantRecord)
			}
			// The delivery admits again whatever was removed.
			if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
				t.Fatalf("clone after redelivery = %d %v, want OK", code, err)
			}
		})
	}
}

// TestRemoteMiss checks that a RemoteMiss reads as the miss it wraps and
// unwraps to it.
func TestRemoteMiss(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "a too-large delta", err: core.ErrDeltaTooLarge},
		{name: "an incompatible platform", err: core.ErrIncompatible},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error = &core.RemoteMiss{Err: tc.err, PreferredHome: "A"}
			if err.Error() != tc.err.Error() {
				t.Fatalf("Error = %q, want %q", err.Error(), tc.err.Error())
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tc.err)
			}
		})
	}
}
