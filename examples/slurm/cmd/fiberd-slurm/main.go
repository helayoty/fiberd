// Command fiberd-slurm is the fiberd agent for a Slurm allocation: the
// agent library (pkg/agent) plus the Slurm home. A job (or its prolog)
// starts it with the grant the issuer minted for this node; it verifies
// the grant offline against the issuer's keys before anything else, stages
// it in the job's grants directory, and serves fibers for as long as the
// allocation lasts. Every fiberd flag applies; the job step's cgroup
// replaces -cgroup-root and the node's address fills -endpoint-host.
//
//	srun --ntasks=1 fiberd-slurm -grant "$FIBERD_GRANT" -verifier jwks -issuer http://issuer:8686 \
//	    -runtime proc -template default=/usr/local/bin/refzygote
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

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/slurm/home"
)

func main() {
	var c agent.Config
	c.Bind(flag.CommandLine)
	grantArg := flag.String("grant", os.Getenv("FIBERD_GRANT"), "the grant for this allocation: a JWT, or @<file>; verified before the agent starts and staged in -grants-dir (default $FIBERD_GRANT)")
	probe := flag.String("slurm-probe", "", "command reporting the job's state as JobState=<STATE> (default: scontrol show job -o $SLURM_JOB_ID; `none` = a timer)")
	flag.Parse()
	c.Finish()
	if err := run(&c, *grantArg, *probe); err != nil {
		log.Fatal(err)
	}
}

func run(c *agent.Config, grantArg, probe string) error {
	job, err := home.ReadJob(os.Getenv)
	if err != nil {
		return err
	}
	if c.GrantsDir == "" {
		c.GrantsDir = home.DefaultGrantsDir(job.ID)
	}
	if grantArg != "" {
		if err := stage(c, grantArg); err != nil {
			return err
		}
	}
	var p []string
	switch probe {
	case "":
		p = nil // the home's default
	case "none":
		p = []string{}
	default:
		p = strings.Fields(probe)
	}
	return agent.Run(c, func(c *agent.Config, _ core.Verifier, _ *grant.Cache) (fhome.Home, error) {
		fam, err := c.Family()
		if err != nil {
			return nil, err
		}
		port, err := c.ListenPort()
		if err != nil {
			return nil, err
		}
		return home.New(home.Config{
			GrantsDir: c.GrantsDir, StaleTTL: c.StaleTTL, Devices: c.Devices, Family: fam, Host: c.EndpointHost,
			ListenPort: port, Probe: p,
		})
	})
}

// stage verifies the grant the job was given and writes it where the
// home's lane picks it up. Verification is what a prolog does: nothing
// runs under a grant this node cannot check.
func stage(c *agent.Config, grantArg string) error {
	tok := grantArg
	if path, ok := strings.CutPrefix(grantArg, "@"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("-grant: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	switch c.Verifier {
	case "jwks":
		if c.Issuer == "" {
			return errors.New("-verifier=jwks needs -issuer to verify -grant")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		v := &grant.Verifier{Cache: &grant.Cache{IssuerURL: c.Issuer}, Audience: c.NodeID, MaxStale: c.JWKSMaxStale}
		g, err := v.Verify(ctx, []byte(tok))
		if err != nil {
			return fmt.Errorf("-grant does not verify for node %s: %w", c.NodeID, err)
		}
		if g.Expired(time.Now()) {
			return fmt.Errorf("-grant %s expired at %s", g.UID, g.LeaseExpiry.Format(time.RFC3339))
		}
		log.Printf("fiberd-slurm: grant %s verified for %s (fibers.max=%d, lease until %s)", g.UID, c.NodeID, g.FiberMax, g.LeaseExpiry.Format(time.RFC3339))
	case "insecure-json":
		log.Printf("fiberd-slurm: -verifier=insecure-json: the grant is staged unverified (development only)")
	default:
		return fmt.Errorf("-verifier %q", c.Verifier)
	}
	if err := os.MkdirAll(c.GrantsDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.GrantsDir, "job.jwt"), []byte(tok+"\n"), 0o600)
}
