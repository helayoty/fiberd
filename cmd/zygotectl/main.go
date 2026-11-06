// Command zygotectl builds, pushes, pulls and inspects zygote artifacts.
//
//	zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -seal-to fleet-pub.json -out out/ref
//	zygotectl build -zygote bin/refzygote -skip-images -out out/bare   runs it to READY, no criu, no key
//	zygotectl build -hyperlight-snapshot snap/ -hyperlight-helper /usr/local/bin/hyperlight-helper -seal-to fleet-pub.json -out out/hl
//	zygotectl push  -dir out/ref -ref http://127.0.0.1:5000/zygotes/ref:v1
//	zygotectl pull  -ref http://127.0.0.1:5000/zygotes/ref@sha256:... -out /tmp/ref
//	zygotectl inspect -dir out/ref
//
// The digest build and push print is the grant's template_digest. The
// images a build takes are sealed to the fleet's public wrap key
// (fleet-pub.json, from grant-issuer keygen -alg A256GCM). The author
// holds nothing that opens them. Only homes, which hold the fleet's seal
// key, do.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/fiberd/internal/cli"
	"github.com/Azure/fiberd/pkg/artifact"
	"github.com/Azure/fiberd/pkg/backend/hyperlight"
	"github.com/Azure/fiberd/pkg/sys/criu"
)

// version is set at link time with -ldflags "-X main.version=v0.1.0".
var version string

func main() {
	os.Exit(run(context.Background(), artifact.Platform{}, os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand. It returns exit code 0 on success or -h,
// 2 for a usage error, and 1 when the subcommand fails. host is what
// build records and inspect judges against. Its empty facts are
// detected when a subcommand needs them, so a test names all three.
func run(ctx context.Context, host artifact.Platform, args []string, stdout, stderr io.Writer) int {
	return cli.Run(args, "usage: zygotectl build|push|pull|inspect [flags], or -version; -h on a subcommand for its flags", map[string]cli.Command{
		"-version":  printVersion(stdout),
		"--version": printVersion(stdout),
		"build":     func(a []string) error { return build(ctx, host, a, stdout, stderr) },
		"push":      func(a []string) error { return push(ctx, a, stdout, stderr) },
		"pull":      func(a []string) error { return pull(ctx, a, stdout, stderr) },
		"inspect":   func(a []string) error { return inspect(host, a, stdout, stderr) },
	}, stderr)
}

func printVersion(stdout io.Writer) cli.Command {
	return func([]string) error {
		_, err := fmt.Fprintln(stdout, "zygotectl", cli.Version(version))
		return err
	}
}

func build(ctx context.Context, host artifact.Platform, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	zygote := fs.String("zygote", "", "zygote executable (linked with libfiberzygote)")
	argv := fs.String("args", "", "arguments the home passes to the zygote")
	out := fs.String("out", "", "artifact directory to write")
	skip := fs.Bool("skip-images", false, "do not checkpoint the zygote (no criu here). It is still run to READY once, as a smoke test")
	noSmoke := fs.Bool("no-smoke", false, "with -skip-images, do not run the zygote at all (a slow warm-up, or a zygote this host cannot run)")
	sealTo := fs.String("seal-to", "", "the fleet's public wrap key (fleet-pub.json, from grant-issuer keygen -alg A256GCM) the images are sealed to. Required unless -skip-images")
	criuBin := fs.String("criu", "criu", "criu binary")
	hlSnapshot := fs.String("hyperlight-snapshot", "", "a Hyperlight guest's snapshot directory, carried as the artifact's sealed images instead of CRIU images, with no -zygote")
	hlHelper := fs.String("hyperlight-helper", "", "with -hyperlight-snapshot, the absolute path of the helper that restores it, as on a home, whose --version facts the artifact records as its platform")
	hlFacts := fs.String("hyperlight-facts", "", "with -hyperlight-snapshot, the helper's --version line itself, for a build host that cannot run the helper as the homes do")
	hlArch := fs.String("hyperlight-arch", "", "with -hyperlight-snapshot, the architecture of the homes that restore it (GOARCH spelling), when it is not this host's")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *hlSnapshot != "" {
		for _, n := range []string{"skip-images", "no-smoke", "criu"} {
			if set[n] {
				return fmt.Errorf("build: -%s is for a zygote's CRIU images, not -hyperlight-snapshot", n)
			}
		}
		return buildHyperlight(ctx, *hlSnapshot, *hlHelper, *hlFacts, *hlArch, *zygote, *argv, *out, *sealTo, host, stdout)
	}
	if *hlHelper != "" || *hlFacts != "" || *hlArch != "" {
		return fmt.Errorf("build: -hyperlight-helper, -hyperlight-facts and -hyperlight-arch go with -hyperlight-snapshot")
	}
	if *zygote == "" || *out == "" {
		return fmt.Errorf("build: -zygote and -out are required")
	}
	if !*skip && *sealTo == "" {
		return fmt.Errorf("build: images are sealed to the fleet's wrap key, so -seal-to fleet-pub.json is required (or -skip-images)")
	}
	var pub *artifact.WrapPublicKey
	if *sealTo != "" {
		var err error
		if pub, err = artifact.LoadWrapPublicKey(*sealTo); err != nil {
			return fmt.Errorf("build: -seal-to: %w", err)
		}
	}
	digest, err := artifact.Build(ctx, artifact.BuildOptions{
		Zygote: *zygote, Args: strings.Fields(*argv), Out: *out, SkipImages: *skip, NoSmoke: *noSmoke,
		SealTo: pub, CRIU: criu.Options{Bin: *criuBin}, Platform: host,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, digest)
	return nil
}

// buildHyperlight builds a Hyperlight snapshot artifact. Its platform is
// the helper's facts, from the helper's --version or given whole, since a
// home checks parity against the helper it runs and not the host the
// artifact was built on. The build host's architecture is kept.
func buildHyperlight(ctx context.Context, snapshot, helper, facts, arch, zygote, argv, out, sealTo string, host artifact.Platform, stdout io.Writer) error {
	switch {
	case out == "":
		return fmt.Errorf("build: -out is required")
	case sealTo == "":
		return fmt.Errorf("build: a Hyperlight snapshot is sealed to the fleet's wrap key, so -seal-to fleet-pub.json is required")
	}
	p, err := helperPlatform(ctx, helper, facts, arch, host)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	for _, a := range strings.Fields(argv) {
		if hyperlight.HelperFlag(a) {
			return fmt.Errorf("build: -args passes %s, which fiberd gives the helper itself and refuses from a template", a)
		}
	}
	pub, err := artifact.LoadWrapPublicKey(sealTo)
	if err != nil {
		return fmt.Errorf("build: -seal-to: %w", err)
	}
	digest, err := artifact.Build(ctx, artifact.BuildOptions{
		HyperlightSnapshot: snapshot, Zygote: zygote, Args: strings.Fields(argv), Out: out, SealTo: pub, Platform: p,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, digest)
	return nil
}

// helperPlatform is the platform a Hyperlight home running the helper
// records: the helper's facts, from its --version or given whole, on
// arch, else this host's architecture.
func helperPlatform(ctx context.Context, helper, facts, arch string, host artifact.Platform) (artifact.Platform, error) {
	if (helper == "") == (facts == "") {
		return artifact.Platform{}, fmt.Errorf("a Hyperlight snapshot needs one of -hyperlight-helper and -hyperlight-facts")
	}
	if helper != "" {
		// The helper runs as a home runs it: from an absolute path, as
		// -hyperlight-helper must be on a home, and with fiberd's own
		// environment, so its facts are the ones a home records.
		if !filepath.IsAbs(helper) {
			return artifact.Platform{}, fmt.Errorf("-hyperlight-helper %q is not an absolute path", helper)
		}
		vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cmd := exec.CommandContext(vctx, helper, "--version")
		cmd.Env = os.Environ()
		b, err := cmd.Output()
		cancel()
		if err != nil {
			return artifact.Platform{}, fmt.Errorf("%s --version: %w", helper, err)
		}
		facts = string(b)
	}
	p, err := hyperlight.PlatformOf(facts)
	if err != nil {
		return artifact.Platform{}, fmt.Errorf("helper facts: %w", err)
	}
	switch arch {
	case "":
		arch = host.Complete().Arch
	case "386", "amd64", "arm", "arm64", "loong64", "mips64le", "ppc64le", "riscv64", "s390x":
	default:
		return artifact.Platform{}, fmt.Errorf("-hyperlight-arch %q is not an architecture homes run (GOARCH spelling, such as amd64 or arm64)", arch)
	}
	p.Arch = arch
	return p, nil
}

func push(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	dir := fs.String("dir", "", "artifact directory from build")
	ref := fs.String("ref", "", "registry reference host/repo:tag (http://host/repo:tag for a plain-http registry)")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *dir == "" || *ref == "" {
		return fmt.Errorf("push: -dir and -ref are required")
	}
	digest, err := artifact.Push(ctx, *dir, *ref)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, digest)
	return nil
}

func pull(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	ref := fs.String("ref", "", "registry reference host/repo@digest or host/repo:tag (http://host/... for a plain-http registry)")
	out := fs.String("out", "", "directory to pull into. Sealed images stay sealed")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *ref == "" || *out == "" {
		return fmt.Errorf("pull: -ref and -out are required")
	}
	cfg, err := artifact.Pull(ctx, *ref, *out)
	if err != nil {
		return err
	}
	return printJSON(stdout, cfg)
}

func inspect(host artifact.Platform, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := fs.String("dir", "", "artifact directory")
	level := fs.String("parity", "strict", "parity level to judge the artifact against this host with (strict, off, kernel=series,...)")
	hlHelper := fs.String("hyperlight-helper", "", "judge a Hyperlight snapshot against a home running this helper, named by its absolute path")
	hlFacts := fs.String("hyperlight-facts", "", "judge a Hyperlight snapshot against a home whose helper prints this --version line")
	hlArch := fs.String("hyperlight-arch", "", "with -hyperlight-helper or -hyperlight-facts, the homes' architecture, when it is not this host's")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("inspect: -dir is required")
	}
	// The architecture names the homes a helper's facts are judged on, so
	// alone it judges nothing, and is refused rather than ignored.
	if *hlArch != "" && *hlHelper == "" && *hlFacts == "" {
		return fmt.Errorf("inspect: -hyperlight-arch goes with -hyperlight-helper or -hyperlight-facts")
	}
	cfg, err := artifact.ReadConfig(*dir)
	if err != nil {
		return err
	}
	if d, err := artifact.ReadDigest(*dir); err == nil {
		cfg.Digest = d
	}
	parity, err := artifact.ParseParity(*level)
	if err != nil {
		return err
	}
	// The verdict a home with this parity level would reach on this host.
	want := cfg.Platform()
	if !cfg.HasImages() {
		want.Kernel, want.Libc = "", ""
	}
	if cfg.ImagesFormat != artifact.ImagesFormatHyperlight && (*hlHelper != "" || *hlFacts != "" || *hlArch != "") {
		return fmt.Errorf("inspect: -hyperlight-helper, -hyperlight-facts and -hyperlight-arch judge a Hyperlight snapshot, and this artifact is not one")
	}
	host = host.Complete()
	verdict := "ok"
	judge := true
	if cfg.ImagesFormat == artifact.ImagesFormatHyperlight {
		// A Hyperlight home's platform is its helper's facts, not this
		// host's kernel and libc.
		if *hlHelper == "" && *hlFacts == "" {
			verdict, judge = "a Hyperlight snapshot: judge it against a helper with -hyperlight-helper or -hyperlight-facts", false
		} else {
			hp, err := helperPlatform(context.Background(), *hlHelper, *hlFacts, *hlArch, host)
			if err != nil {
				return fmt.Errorf("inspect: %w", err)
			}
			host = hp
		}
	}
	if judge {
		if err := parity.Check(host, want); err != nil {
			verdict = err.Error()
		}
	}
	return printJSON(stdout, struct {
		Digest string            `json:"digest"`
		Config artifact.Config   `json:"config"`
		Host   artifact.Platform `json:"host"`
		Parity string            `json:"parity"`
		Usable string            `json:"usable_here"`
	}{cfg.Digest, cfg, host, parity.String(), verdict})
}

func printJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, string(b))
	return nil
}
