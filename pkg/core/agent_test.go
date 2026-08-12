package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

type nopAudit struct{}

func (nopAudit) Append(context.Context, string, Fence, string) error { return nil }

type acceptVerifier struct{}

func (acceptVerifier) Verify(context.Context, []byte, string) error { return nil }

type fakeRuntime struct{ tier Tier }

func (f fakeRuntime) Tier() Tier { return f.tier }

func (f fakeRuntime) Clone(_ context.Context, _ string, _ CloneSource, _ string, fence Fence, _ time.Duration) (FiberHandle, error) {
	return FiberHandle{ID: fence.String(), Endpoint: "127.0.0.1:1"}, nil
}

func (fakeRuntime) Park(context.Context, string, bool) (string, error) { return "", nil }

func (fakeRuntime) Release(context.Context, string) error { return nil }

func (fakeRuntime) List(context.Context, string) ([]FiberHandle, error) { return nil, nil }

func TestCloneMissHealth(t *testing.T) {
	const grant = "g1"
	cases := []struct {
		name      string
		health    string // "up" | "down" | "nil"
		basicTier bool
		noSandbox bool
		setup     func(t *testing.T, a *Agent)
		grant     string
		session   string
		want      StatusCode
		wantErr   error
	}{
		{
			name:    "unknown healthy is fallback",
			health:  "up",
			grant:   "nope",
			want:    DeferredFallback,
			wantErr: ErrGrantUnknown,
		},
		{
			name:    "unknown unhealthy is shed",
			health:  "down",
			grant:   "nope",
			want:    Shed,
			wantErr: ErrGrantUnknown,
		},
		{
			name:    "unknown nil health fails toward fallback",
			health:  "nil",
			grant:   "nope",
			want:    DeferredFallback,
			wantErr: ErrGrantUnknown,
		},
		{
			name:   "full healthy is fallback",
			health: "up",
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
				createFiber(t, a.Ledger, grant, "", "f1")
			},
			grant:   grant,
			want:    DeferredFallback,
			wantErr: ErrGrantFull,
		},
		{
			name:   "full unhealthy is shed",
			health: "down",
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
				createFiber(t, a.Ledger, grant, "", "f1")
			},
			grant:   grant,
			want:    Shed,
			wantErr: ErrGrantFull,
		},
		{
			name:   "full nil health fails toward fallback",
			health: "nil",
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
				createFiber(t, a.Ledger, grant, "", "f1")
			},
			grant:   grant,
			want:    DeferredFallback,
			wantErr: ErrGrantFull,
		},
		{
			name:   "create unhealthy still ok",
			health: "down",
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
			},
			grant: grant,
			want:  OK,
		},
		{
			name:      "sandbox missing healthy is fallback",
			health:    "up",
			noSandbox: true,
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
			},
			grant:   grant,
			want:    DeferredFallback,
			wantErr: ErrGrantUnknown,
		},
		{
			name:      "sandbox missing unhealthy is shed",
			health:    "down",
			noSandbox: true,
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
			},
			grant:   grant,
			want:    Shed,
			wantErr: ErrGrantUnknown,
		},
		{
			name:      "needs tier unhealthy still fallback",
			health:    "down",
			basicTier: true,
			setup: func(t *testing.T, a *Agent) {
				a.Ledger.AdmitGrant(grant, "sbx-"+grant, 1)
				createFiber(t, a.Ledger, grant, "S1", "f1")
				a.Ledger.OnPark("f1", "delta-f1")
			},
			grant:   grant,
			session: "S1",
			want:    DeferredFallback,
			wantErr: ErrNeedsTier,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := fakeRuntime{tier: TierCheckpoint}
			if tc.basicTier {
				rt.tier = TierBasic
			}
			a := &Agent{
				Ledger:  NewLedger(1),
				Budget:  NewBudget(1000, 256<<20),
				Runtime: rt,
				Audit:   nopAudit{},
				Verify:  acceptVerifier{},
				Health:  testHealth(tc.health),
				SandboxFor: func(uid string) (string, bool) {
					return "sbx-" + uid, !tc.noSandbox
				},
			}
			if tc.setup != nil {
				tc.setup(t, a)
			}

			_, code, err := a.Clone(context.Background(), nil, CloneRequest{
				GrantUID: tc.grant, Session: tc.session, Deadline: time.Second,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("Clone code = %d, want %d", code, tc.want)
			}
		})
	}
}

func testHealth(kind string) *SourceHealth {
	switch kind {
	case "nil":
		return nil
	case "down":
		h := NewSourceHealth(10*time.Second, time.Now())
		h.MarkSync(time.Now().Add(-10 * time.Second))
		return h
	default:
		return NewSourceHealth(10*time.Second, time.Now())
	}
}
