// Command zygotectl builds, pushes, pulls and inspects zygote artifacts.
//
//	zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -out out/ref
//	zygotectl push  -dir out/ref -ref http://127.0.0.1:5000/zygotes/ref:v1
//	zygotectl pull  -ref http://127.0.0.1:5000/zygotes/ref@sha256:... -out /tmp/ref
//	zygotectl inspect -dir out/ref
//
// The digest build and push print is the grant's template_digest.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/helayoty/fiberd/internal/cli"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/sys/criu"
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
	skip := fs.Bool("skip-images", false, "do not checkpoint the zygote (no criu here)")
	criuBin := fs.String("criu", "criu", "criu binary")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *zygote == "" || *out == "" {
		return fmt.Errorf("build: -zygote and -out are required")
	}
	digest, err := artifact.Build(ctx, artifact.BuildOptions{
		Zygote: *zygote, Args: strings.Fields(*argv), Out: *out, SkipImages: *skip,
		CRIU: criu.Options{Bin: *criuBin}, Platform: host,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, digest)
	return nil
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
	out := fs.String("out", "", "directory to unpack into")
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
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("inspect: -dir is required")
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
	if !cfg.HasImages {
		want.Kernel, want.Libc = "", ""
	}
	host = host.Complete()
	verdict := "ok"
	if err := parity.Check(host, want); err != nil {
		verdict = err.Error()
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
