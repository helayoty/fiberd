package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// advisedRuntime is a deadlineRuntime that advises its own defaults, like
// a runtime whose create is slower than a fork.
type advisedRuntime struct {
	deadlineRuntime
	create, resume time.Duration
}

func (r advisedRuntime) DefaultDeadlines() (time.Duration, time.Duration) { return r.create, r.resume }

// TestCloneDefaultDeadlines checks the deadline the runtime is given. The
// caller's own deadline is always honoured. Without one, a create gets the
// create default and a resume the resume default, from the runtime when
// it advises both, else from the core.
func TestCloneDefaultDeadlines(t *testing.T) {
	cases := []struct {
		name     string
		deadline time.Duration // the request's
		advise   bool
		create   time.Duration // advised
		resume   time.Duration // advised
		resumeS  bool          // the session is parked, so the clone resumes it
		want     time.Duration
	}{
		{name: "the caller's deadline is honoured over advice", deadline: 300 * time.Millisecond, advise: true, create: 5 * time.Second, resume: 9 * time.Second,
			want: 300 * time.Millisecond},
		{name: "a create without a deadline gets the core default", want: core.DefaultCreateDeadline},
		{name: "a resume without a deadline gets the core default", resumeS: true, want: core.DefaultResumeDeadline},
		{name: "a create without a deadline gets the runtime's advice", advise: true, create: 5 * time.Second, resume: 9 * time.Second,
			want: 5 * time.Second},
		{name: "a resume without a deadline gets the runtime's advice", advise: true, create: 5 * time.Second, resume: 9 * time.Second,
			resumeS: true, want: 9 * time.Second},
		{name: "advice with a zero create is ignored", advise: true, resume: 9 * time.Second, want: core.DefaultCreateDeadline},
		{name: "advice with a zero resume is ignored", advise: true, create: 5 * time.Second, resumeS: true, want: core.DefaultResumeDeadline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 2}
			a := newAgent(t, "up", core.TierCheckpoint, g)
			var spec core.CloneSpec
			dr := deadlineRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)}, spec: &spec}
			a.Runtime = dr
			if tc.advise {
				a.Runtime = advisedRuntime{deadlineRuntime: dr, create: tc.create, resume: tc.resume}
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
// waits for the test, and then answers err.
type prepRuntime struct {
	fakeRuntime
	started chan struct{}
	proceed chan struct{}
	err     error
}

func (r prepRuntime) PrepareTemplate(context.Context, core.Grant) error {
	r.started <- struct{}{}
	<-r.proceed
	return r.err
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
// waits for the first instead of warming the template again, and answers
// what the first left behind. A second whose context ends stops waiting.
func TestAdmitWaitsForInflight(t *testing.T) {
	cases := []struct {
		name         string
		firstErr     error // what the first admission's template warm answers
		cancelSecond bool
		wantFirst    core.StatusCode
		wantSecond   core.StatusCode
		wantErr      error // the second's
		wantAdmitted bool
	}{
		{name: "the second shares the first's success", wantFirst: core.OK, wantSecond: core.OK, wantAdmitted: true},
		{name: "the second shares the first's failure", firstErr: errors.New("pull: manifest unknown"),
			wantFirst: core.DeferredFallback, wantSecond: core.DeferredFallback, wantErr: core.ErrNotReady},
		{name: "a second whose context ends stops waiting", cancelSecond: true,
			wantFirst: core.OK, wantSecond: core.DeferredFallback, wantErr: context.Canceled, wantAdmitted: true},
	}
	type result struct {
		code core.StatusCode
		err  error
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a"}
			a := newAgent(t, "up", core.TierCheckpoint)
			rt := prepRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, started: make(chan struct{}, 2), proceed: make(chan struct{}), err: tc.firstErr}
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
			second := make(chan result, 1)
			go func() {
				code, err := a.Admit(ctx, g)
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
			if n := len(rt.started); n != 0 {
				t.Fatalf("the template was warmed %d more times, want once in all", n)
			}
			if _, ok := a.Ledger.Grant("g1"); ok != tc.wantAdmitted {
				t.Fatalf("admitted = %v, want %v", ok, tc.wantAdmitted)
			}
		})
	}
}

// admitRuntime warms templates with prepErr, offers the device classes in
// offers, and records the fabric channels it is given.
type admitRuntime struct {
	fakeRuntime
	prepErr  error
	offers   map[string]bool
	attached []core.FabricChannel
}

func (r *admitRuntime) PrepareTemplate(context.Context, core.Grant) error { return r.prepErr }
func (r *admitRuntime) OffersDevice(_, class string) bool                 { return r.offers[class] }
func (r *admitRuntime) AttachFabric(_ string, fc core.FabricChannel) {
	r.attached = append(r.attached, fc)
}

// TestAdmitOutcomes checks what Admit answers and what becomes of the
// grant's fabric channel. A grant refused after provisioning gives its
// channel back, a re-delivery releases the channel it replaces, and a
// device budget is admitted only where the template offers the class.
func TestAdmitOutcomes(t *testing.T) {
	gpu := core.DeviceBudget{Bytes: 1 << 30, Class: "gpu"}
	cases := []struct {
		name         string
		health       string
		plain        bool // the runtime takes no fabric and offers no device
		fabricErr    error
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
		{name: "a fabric is provisioned and attached to a runtime that takes one",
			want: core.OK, wantAdmitted: true, provisioned: 1, attached: 1},
		{name: "a fabric on a runtime that takes none is provisioned only", plain: true,
			want: core.OK, wantAdmitted: true, provisioned: 1},
		{name: "a fabric that cannot be provisioned is not ready", fabricErr: errors.New("claim pending"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, provisioned: 1},
		{name: "a fabric that cannot be provisioned with the lane down is shed", health: "down", fabricErr: errors.New("claim pending"),
			want: core.Shed, wantErr: core.ErrNotReady, provisioned: 1},
		{name: "a template that fails to warm releases the fabric", prepErr: errors.New("pull: manifest unknown"),
			want: core.DeferredFallback, wantErr: core.ErrNotReady, provisioned: 1, released: 1, attached: 1},
		{name: "a re-delivery releases the fabric it replaces", admits: 2,
			want: core.OK, wantAdmitted: true, provisioned: 2, released: 1, attached: 2},
		{name: "a device class the template offers is admitted", device: gpu, offers: map[string]bool{"gpu": true},
			want: core.OK, wantAdmitted: true, provisioned: 1, attached: 1},
		{name: "a device class the template does not offer is needs-tier, and the fabric is released", device: gpu, offers: map[string]bool{"sim": true},
			want: core.NeedsTier, wantErr: core.ErrNeedsDevice, provisioned: 1, released: 1, attached: 1},
		{name: "a device budget on a runtime with no device is needs-tier, and the fabric is released", plain: true, device: gpu,
			want: core.NeedsTier, wantErr: core.ErrNeedsDevice, provisioned: 1, released: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			health := tc.health
			if health == "" {
				health = "up"
			}
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", DeviceBudget: tc.device}
			a := newAgent(t, health, core.TierCheckpoint)
			rt := &admitRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, prepErr: tc.prepErr, offers: tc.offers}
			if tc.plain {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint}
			} else {
				a.Runtime = rt
			}
			var provisioned, released int
			a.Fabric = func(context.Context, core.Grant) (core.FabricChannel, func(), error) {
				provisioned++
				if tc.fabricErr != nil {
					return core.FabricChannel{}, nil, tc.fabricErr
				}
				return core.FabricChannel{Kind: "static", Devices: []string{"/dev/sim0"}}, func() { released++ }, nil
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
				t.Fatalf("fabric provisioned=%d released=%d attached=%d, want %d %d %d",
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
			a := newAgent(t, "up", core.TierCheckpoint, g)
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
			a := newAgent(t, "up", core.TierCheckpoint, g)
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

// TestRedeliver checks that the lane delivering a grant again lifts its
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
			a := newAgent(t, "up", core.TierCheckpoint, g)
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
			// The lane's delivery admits again whatever was removed.
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
