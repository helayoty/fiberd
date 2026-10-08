// Command audit-verify checks a home's audit spool. It verifies the hash
// chain, the sequence numbers, the gaps, and every checkpoint's signature.
//
//	audit-verify -spool /var/lib/fiberd/private/audit.jsonl -trust audit-key.json
//
// It exits 1 when the spool does not verify, has records but no
// checkpoint, or has records before its chain started. Records cut after
// the last checkpoint need an anchor kept off the host.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run prints the report to stdout and why the spool fails to stderr. It
// returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spool := fs.String("spool", "/var/lib/fiberd/private/audit.jsonl", "the audit spool to check")
	trust := fs.String("trust", "", "JWK or JWKS of the Ed25519 keys checkpoints may be signed with (required). A private JWK counts as its public half")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "audit-verify: "+format+"\n", a...)
		return 1
	}
	if *trust == "" {
		return fail("-trust is required")
	}
	keys, err := loadTrust(*trust)
	if err != nil {
		return fail("%v", err)
	}
	rep, err := core.VerifySpool(*spool, keys)
	if err != nil {
		return fail("%v", err)
	}
	_, _ = fmt.Fprintf(stdout, "%s: %d chained records, %d checkpoints; signed through seq %d, %d records after it\n",
		*spool, rep.Records, rep.Checkpoints, rep.SignedSeq, rep.Unsigned)
	if rep.Unchained > 0 {
		_, _ = fmt.Fprintf(stdout, "  %d records before the chain started are not covered\n", rep.Unchained)
	}
	for _, g := range rep.Gaps {
		if g.Lost != nil {
			_, _ = fmt.Fprintf(stdout, "  gap at seq %d: seq %d-%d not written: %s\n", g.Seq, g.Lost.From, g.Lost.To, g.Detail)
		} else {
			_, _ = fmt.Fprintf(stdout, "  gap at seq %d: %s\n", g.Seq, g.Detail)
		}
	}
	if rep.TornTail {
		_, _ = fmt.Fprintln(stdout, "  the last line is unreadable; the home records a gap when it next opens the spool")
	}
	switch {
	case rep.Unchained > 0:
		return fail("%s: %d records are not chained, so no checkpoint covers them", *spool, rep.Unchained)
	case rep.Records > 0 && rep.Checkpoints == 0:
		return fail("%s: no checkpoint, so nothing in it is signed", *spool)
	}
	return 0
}

func loadTrust(path string) (map[string]ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil || len(set.Keys) == 0 {
		var k jose.JSONWebKey
		if err := json.Unmarshal(b, &k); err != nil {
			return nil, fmt.Errorf("-trust %s: neither a JWK nor a JWKS: %w", path, err)
		}
		set.Keys = []jose.JSONWebKey{k}
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		pub, ok := k.Public().Key.(ed25519.PublicKey)
		if !ok || k.KeyID == "" {
			return nil, fmt.Errorf("-trust %s: key %q is not an Ed25519 key with a kid", path, k.KeyID)
		}
		keys[k.KeyID] = pub
	}
	return keys, nil
}
