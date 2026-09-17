// Command zygotectl builds, pushes, pulls and inspects zygote artifacts.
//
//	zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -out out/ref
//	zygotectl push  -dir out/ref -ref 127.0.0.1:5000/zygotes/ref:v1 -plain-http
//	zygotectl pull  -ref 127.0.0.1:5000/zygotes/ref@sha256:... -out /tmp/ref -plain-http
//	zygotectl inspect -dir out/ref
//
// The digest build and push print is the grant's template_digest.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "build":
		err = build(os.Args[2:])
	case "push":
		err = push(os.Args[2:])
	case "pull":
		err = pull(os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zygotectl build|push|pull|inspect [flags]; -h on a subcommand for its flags")
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	zygote := fs.String("zygote", "", "zygote executable (linked with libfiberzygote)")
	argv := fs.String("args", "", "arguments the home passes to the zygote")
	out := fs.String("out", "", "artifact directory to write")
	skip := fs.Bool("skip-images", false, "do not checkpoint the zygote (no criu here)")
	criuBin := fs.String("criu", "criu", "criu binary")
	_ = fs.Parse(args)
	if *zygote == "" || *out == "" {
		return fmt.Errorf("build: -zygote and -out are required")
	}
	digest, err := artifact.Build(context.Background(), artifact.BuildOptions{
		Zygote: *zygote, Args: strings.Fields(*argv), Out: *out, SkipImages: *skip,
		CRIU: criu.Options{Bin: *criuBin},
	})
	if err != nil {
		return err
	}
	fmt.Println(digest)
	return nil
}

func push(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	dir := fs.String("dir", "", "artifact directory from build")
	ref := fs.String("ref", "", "registry reference host/repo:tag")
	plain := fs.Bool("plain-http", false, "registry speaks http, not https")
	_ = fs.Parse(args)
	if *dir == "" || *ref == "" {
		return fmt.Errorf("push: -dir and -ref are required")
	}
	digest, err := artifact.Push(context.Background(), *dir, *ref, *plain)
	if err != nil {
		return err
	}
	fmt.Println(digest)
	return nil
}

func pull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	ref := fs.String("ref", "", "registry reference host/repo@digest or host/repo:tag")
	out := fs.String("out", "", "directory to unpack into")
	plain := fs.Bool("plain-http", false, "registry speaks http, not https")
	_ = fs.Parse(args)
	if *ref == "" || *out == "" {
		return fmt.Errorf("pull: -ref and -out are required")
	}
	cfg, err := artifact.Pull(context.Background(), *ref, *out, *plain)
	if err != nil {
		return err
	}
	return print(cfg)
}

func inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	dir := fs.String("dir", "", "artifact directory")
	level := fs.String("parity", "strict", "parity level to judge the artifact against this host with (strict, off, kernel=series,...)")
	_ = fs.Parse(args)
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
	verdict := "ok"
	if err := parity.Check(artifact.Host(), want); err != nil {
		verdict = err.Error()
	}
	return print(struct {
		Digest string            `json:"digest"`
		Config artifact.Config   `json:"config"`
		Host   artifact.Platform `json:"host"`
		Parity string            `json:"parity"`
		Usable string            `json:"usable_here"`
	}{cfg.Digest, cfg, artifact.Host(), parity.String(), verdict})
}

func print(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
