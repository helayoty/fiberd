// Command fiberd-slurm is fiberd for a Slurm allocation: the
// library (pkg/fiberd) plus the Slurm home. A job (or its prolog)
// starts it with the grant the issuer minted for this node; it verifies
// the grant offline against the issuer's keys before anything else, stages
// it in the job's grants directory, and serves fibers for as long as the
// allocation lasts. Every fiberd flag applies; the job step's cgroup
// replaces -cgroup-root and the node's address fills -endpoint-host.
//
//	srun --ntasks=1 fiberd-slurm -grant "$FIBERD_GRANT" -verifier jwks -issuer http://issuer:8686 \
//	    -insecure-plaintext -runtime proc -template default=/usr/local/bin/refzygote
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/slurm/home"
)

func main() {
	var c fiberd.Config
	fs := flag.NewFlagSet("fiberd-slurm", flag.ContinueOnError)
	c.Bind(fs)
	grantArg := fs.String("grant", os.Getenv("FIBERD_GRANT"), "the grant for this allocation: a JWT, or @<file>; verified before fiberd starts and staged in -grants-dir (default $FIBERD_GRANT)")
	probe := fs.String("slurm-probe", "", "command reporting the job's state as JobState=<STATE> (default: scontrol show job -o $SLURM_JOB_ID; `none` = a timer)")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		err = usageError{err}
	} else {
		err = run(context.Background(), &c, *grantArg, *probe, os.Getenv, home.Config{})
	}
	code := exitCode(err)
	if code == 1 {
		log.Print(err)
	}
	os.Exit(code)
}

// usageError is a bad command line, already reported with the usage.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

// exitCode is the process's exit status for what main got back. It is 0
// for success and -h, 2 for a bad command line and 1 for any other
// failure.
func exitCode(err error) int {
	var usage usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usage):
		return 2
	default:
		return 1
	}
}

// run is fiberd under a Slurm allocation until ctx ends or the job does.
// env reads the job's environment. base carries what a test overrides in
// the home, which is the cgroup v2 mount the job step's cgroup is
// delegated under, the probe runner and what happens when the job ends.
// main passes the zero value, so the home's defaults apply and no test
// touches the host's cgroups.
func run(ctx context.Context, c *fiberd.Config, grantArg, probe string, env func(string) string, base home.Config) error {
	job, err := home.ReadJob(env)
	if err != nil {
		return err
	}
	if c.Node.GrantsDir == "" {
		c.Node.GrantsDir = home.DefaultGrantsDir(job.ID)
	}
	if grantArg != "" {
		if err := stage(c, grantArg); err != nil {
			return err
		}
	}
	p := probeCommand(probe)
	return fiberd.RunContext(ctx, c, func(c *fiberd.Config, _ *grant.Cache) (fhome.Home, error) {
		fam, err := c.Family()
		if err != nil {
			return nil, err
		}
		cfg := base
		cfg.Env, cfg.GrantsDir, cfg.StaleTTL, cfg.Devices = env, c.Node.GrantsDir, c.Node.StaleTTL, c.Node.Devices
		cfg.Family, cfg.Host, cfg.Probe = fam, c.Endpoint.Host, p
		return home.New(cfg)
	})
}

// probeCommand reads -slurm-probe. Empty is nil, the home's default
// (scontrol). `none` is an empty command, so liveness comes from a timer.
// Anything else is split into the command and its arguments.
func probeCommand(probe string) []string {
	switch probe {
	case "":
		return nil
	case "none":
		return []string{}
	default:
		return strings.Fields(probe)
	}
}

// stage verifies the grant the job was given and writes it where the
// home's grant directory picks it up. Verification is what a prolog does: nothing
// runs under a grant this node cannot check.
func stage(c *fiberd.Config, grantArg string) error {
	tok := grantArg
	if path, ok := strings.CutPrefix(grantArg, "@"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("-grant: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	switch c.Trust.Verifier {
	case "jwks":
		if c.Trust.Issuer == "" {
			return errors.New("-verifier=jwks needs -issuer to verify -grant")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		v := &grant.Verifier{Cache: &grant.Cache{IssuerURL: c.Trust.Issuer}, Audience: c.Node.ID, MaxStale: c.Trust.JWKSMaxStale}
		g, err := v.Verify(ctx, []byte(tok))
		if err != nil {
			return fmt.Errorf("-grant does not verify for node %s: %w", c.Node.ID, err)
		}
		if g.Expired(time.Now()) {
			return fmt.Errorf("-grant %s expired at %s", g.UID, g.LeaseExpiry.Format(time.RFC3339))
		}
		log.Printf("fiberd-slurm: grant %s verified for %s (fibers.max=%d, lease until %s)", g.UID, c.Node.ID, g.FiberMax, g.LeaseExpiry.Format(time.RFC3339))
	case "insecure-json":
		log.Printf("fiberd-slurm: -verifier=insecure-json: the grant is staged unverified (development only)")
	default:
		return fmt.Errorf("-verifier %q", c.Trust.Verifier)
	}
	if err := os.MkdirAll(c.Node.GrantsDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Node.GrantsDir, "job.jwt"), []byte(tok+"\n"), 0o600)
}
