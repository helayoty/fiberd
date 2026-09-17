package standalone_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/standalone"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

func TestStandaloneGrantsDirDrivesAdmission(t *testing.T) {
	key, _ := grant.GenerateKey(jose.EdDSA)
	is := &grant.Issuer{Key: key, URL: "https://issuer.test"}
	dir := t.TempDir()
	h := standalone.New(standalone.Config{GrantsDir: dir, Poll: 20 * time.Millisecond, StaleTTL: time.Second})

	// A verifier that trusts this issuer's key directly (no network).
	pub := key.Public()
	ver := verifierFunc(func(_ context.Context, tok []byte) (core.Grant, error) {
		return grant.Verify(string(tok), &pub, grant.VerifyOptions{Audience: "node-a"})
	})
	a := &core.Agent{NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(100, 1<<20),
		Runtime: stub.New(), Audit: core.NopAuditor{}, Verify: ver, Health: h.Health()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go home.Drive(ctx, h, a)

	tok, err := is.Mint(core.Grant{UID: "pre-1", Audience: "node-a", FiberMax: 1, LeaseExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pre-1.jwt")
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, ok := a.Ledger.Grant("pre-1"); return ok }, "grant admitted from the directory")

	// A token that does not verify (wrong audience) is logged, not admitted.
	bad, _ := is.Mint(core.Grant{UID: "bad-1", Audience: "node-z", LeaseExpiry: time.Now().Add(time.Hour)})
	_ = os.WriteFile(filepath.Join(dir, "bad-1.jwt"), []byte(bad), 0o600)
	time.Sleep(60 * time.Millisecond)
	if _, ok := a.Ledger.Grant("bad-1"); ok {
		t.Fatal("unverified grant admitted")
	}

	// Removing the file revokes the grant.
	_ = os.Remove(path)
	waitFor(t, func() bool { _, ok := a.Ledger.Grant("pre-1"); return !ok }, "grant revoked after file removal")
}

func TestStandaloneLaneOverrideAndTimer(t *testing.T) {
	h := standalone.New(standalone.Config{StaleTTL: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	if !h.Health().Healthy(time.Now()) {
		t.Fatal("fresh home must be healthy")
	}
	h.SetLane(false)
	if h.Health().Healthy(time.Now()) {
		t.Fatal("SetLane(false) must make the lane stale immediately")
	}
	// The timer keeps ticking but is ignored while paused.
	time.Sleep(300 * time.Millisecond)
	if h.Health().Healthy(time.Now()) {
		t.Fatal("paused lane must stay stale despite the timer")
	}
	h.SetLane(true)
	if !h.Health().Healthy(time.Now()) {
		t.Fatal("SetLane(true) must recover the lane")
	}
}

type verifierFunc func(context.Context, []byte) (core.Grant, error)

func (f verifierFunc) Verify(ctx context.Context, tok []byte) (core.Grant, error) { return f(ctx, tok) }

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}
