package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

var (
	target     = flag.String("target", "", "host:port of the Fibers service under test (required)")
	targetTier = flag.String("target-tier", "FIBER_CHECKPOINT", "tier the target advertises")
	nodeID     = flag.String("node-id", "", "audience for minted grants: the target's node id (required)")
	template   = flag.String("template", "sha256:conform", "template digest for minted grants")
	mint       = flag.String("mint", "insecure-json", "how to mint grants: jwt (sign with -issuer-key as -issuer) or insecure-json")
	issuerKey  = flag.String("issuer-key", "", "private JWK for -mint=jwt (from grant-issuer keygen)")
	issuerURL  = flag.String("issuer", "", "issuer URL for -mint=jwt: what the target verifies against")
	restartCmd = flag.String("restart-cmd", "", "hook: restart the target in place")
	healthCmd  = flag.String("cp-health-cmd", "", "hook: $1 = up|down sets grant-lane health")
	auditCmd   = flag.String("audit-cmd", "", "hook: $1 = event, $2 = fence; exit 0 if the audit record exists")
	auditFile  = flag.String("audit-file", "", "path to the target's audit.jsonl (local alternative to -audit-cmd)")
	engineCmd  = flag.String("engine-kill-cmd", "", "hook: $1 = grant uid; end the grant's warm template instance (its engine) as a crash would")
	scopeCmd   = flag.String("scope-cmd", "", "hook: the home's scope is lost while it runs (namespace, fabric claim); it must revoke every fence")
	caseTO     = flag.Duration("case-timeout", 15*time.Second, "per-case timeout")
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func sh(ctx context.Context, cmd string, args ...string) error {
	c := exec.CommandContext(ctx, "sh", append([]string{"-c", cmd, "conform"}, args...)...)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	return c.Run()
}

func TestConformance(t *testing.T) {
	if *target == "" {
		t.Skip("no -target: nothing to conform (this is the grant-conform binary; see tests/conform/main.go)")
	}
	if *nodeID == "" {
		t.Fatal("-node-id is required")
	}
	tier, err := core.ParseTier(*targetTier)
	if err != nil {
		t.Fatal(err)
	}
	d := Driver{Target: *target, TargetTier: tier, NodeID: *nodeID, Template: *template, Timeout: *caseTO}

	switch *mint {
	case "insecure-json":
		d.Mint = func(g core.Grant) (string, error) {
			b, err := protojson.Marshal(grant.ToProto(g))
			return string(b), err
		}
	case "jwt":
		if *issuerKey == "" || *issuerURL == "" {
			t.Fatal("-mint=jwt needs -issuer-key and -issuer")
		}
		key, err := grant.LoadKey(*issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		is := &grant.Issuer{Key: key, URL: *issuerURL}
		d.Mint = is.Mint
	default:
		t.Fatalf("unknown -mint %q", *mint)
	}
	if *restartCmd != "" {
		cmd := *restartCmd
		d.Restart = func(ctx context.Context) error { return sh(ctx, cmd) }
	}
	if *healthCmd != "" {
		cmd := *healthCmd
		d.SetCPHealth = func(ctx context.Context, healthy bool) error {
			arg := "down"
			if healthy {
				arg = "up"
			}
			return sh(ctx, cmd, arg)
		}
	}
	if *engineCmd != "" {
		cmd := *engineCmd
		d.EngineKill = func(ctx context.Context, grantUID string) error { return sh(ctx, cmd, grantUID) }
	}
	if *scopeCmd != "" {
		cmd := *scopeCmd
		d.ScopeLost = func(ctx context.Context) error { return sh(ctx, cmd) }
	}
	switch {
	case *auditCmd != "":
		cmd := *auditCmd
		d.AuditHas = func(ctx context.Context, event string, f core.Fence) (bool, error) {
			err := sh(ctx, cmd, event, f.String())
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return false, nil
			}
			return err == nil, err
		}
	case *auditFile != "":
		path := *auditFile
		d.AuditHas = func(_ context.Context, event string, f core.Fence) (bool, error) {
			return auditFileHas(path, event, f)
		}
	}
	Run(t, d)
}

func auditFileHas(path, event string, f core.Fence) (bool, error) {
	fh, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("audit file: %w", err)
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r core.AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if r.Event == event && r.Fence == f {
			return true, nil
		}
	}
	return false, sc.Err()
}
