package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"

	"github.com/helayoty/fiberd/internal/cli"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	kubehome "github.com/helayoty/fiberd/pkg/home/kubernetes"
)

// The forms fiberd runs in, besides fiberd run.
const (
	serveCmd   = "fiberd"
	healthzCmd = "healthz"
	readyzCmd  = "readyz"
)

// standaloneHome is the -home default, a plain host.
const standaloneHome = "standalone"

// probeTimeout bounds one healthz or readyz call. The Pod's probe
// timeoutSeconds must exceed it, and the controller sets it so.
const probeTimeout = 5 * time.Second

// env is what run takes from the host. Tests replace each part.
type env struct {
	// getenv reads the downward API's POD_* variables.
	getenv func(string) string
	// askAdmin asks a running fiberd's admin socket for /healthz or
	// /readyz, named by path.
	askAdmin func(ctx context.Context, c *fiberd.Config, path string) error
	// newKube builds the API client a kubernetes home talks through.
	newKube func(ctx context.Context) (kubehome.Kube, error)
	// newHome builds the kubernetes home from its config.
	newHome func(cfg kubehome.Config) (home.Home, error)
	// runFiberd runs fiberd with the home the factory builds.
	runFiberd func(ctx context.Context, c *fiberd.Config, newHome fiberd.HomeFactory) error
}

// hostEnv is the real host.
func hostEnv() env {
	return env{getenv: os.Getenv, askAdmin: askAdmin, newKube: inClusterKube, newHome: newKubeHome, runFiberd: fiberd.RunContext}
}

// askAdmin is Config.Readyz for readyz and Config.Healthz otherwise.
func askAdmin(ctx context.Context, c *fiberd.Config, path string) error {
	if path == readyzCmd {
		return c.Readyz(ctx)
	}
	return c.Healthz(ctx)
}

// inClusterKube is the API client from the Pod's service account.
func inClusterKube(ctx context.Context) (kubehome.Kube, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return kubehome.NewKube(ctx, cfg)
}

// newKubeHome is kubehome.New as a home.Home. A failed New is a nil
// interface, never a nil *Home inside one.
func newKubeHome(cfg kubehome.Config) (home.Home, error) {
	h, err := kubehome.New(cfg)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// options is every flag fiberd takes. fiberd.Config holds fiberd's own.
// The rest pick the home and say who it is.
type options struct {
	fiberd  fiberd.Config
	home    string      // -home
	pod     podIdentity // -pod-name, -pod-namespace, -pod-uid
	version bool        // -version
}

// podIdentity is who a kubernetes home is. A grant Pod learns it from
// the downward API.
type podIdentity struct{ Name, Namespace, UID string }

// flagError is a flag error the flag package has already reported.
type flagError struct{ error }

// buildConfig parses args for the form cmd and checks them. Serving with
// -home kubernetes needs the whole Pod identity. Without -node-id the
// Pod name is the node id, so a grant's audience names the Pod. Without
// -cgroup-root the home reads the container's own cgroup. The probe
// forms need no identity. -version skips the checks.
func buildConfig(cmd string, args []string, getenv func(string) string, stderr io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	o.bind(fs, getenv)
	fs.Usage = func() { usage(fs, cmd) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, flagError{err}
	}
	if o.version {
		return o, nil
	}
	if fs.NArg() > 0 {
		help := "fiberd -h"
		if cmd != serveCmd {
			help = "fiberd " + cmd + " -h"
		}
		return nil, fmt.Errorf("unexpected argument %q, see %s", fs.Arg(0), help)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch o.home {
	case standaloneHome:
	case kubehome.Name:
		if cmd != serveCmd {
			break
		}
		if err := o.pod.check(); err != nil {
			return nil, err
		}
		if !set["node-id"] {
			o.fiberd.Node.ID = o.pod.Name
		}
		if !set["cgroup-root"] {
			o.fiberd.Node.CgroupRoot = ""
		}
	default:
		return nil, fmt.Errorf("-home %q unknown, want %s or %s", o.home, standaloneHome, kubehome.Name)
	}
	return o, nil
}

// bind registers fiberd's own flags on fs, then the home's beside them.
// The Pod flags default to the downward API's variables.
func (o *options) bind(fs *flag.FlagSet, getenv func(string) string) {
	o.fiberd.Bind(fs)
	fs.StringVar(&o.home, "home", standaloneHome, "the home fiberd runs in, standalone or kubernetes")
	fs.StringVar(&o.pod.Name, "pod-name", getenv("POD_NAME"), "this grant Pod's name, for -home kubernetes. The downward API fills it through POD_NAME")
	fs.StringVar(&o.pod.Namespace, "pod-namespace", getenv("POD_NAMESPACE"), "this grant Pod's namespace, for -home kubernetes. The downward API fills it through POD_NAMESPACE")
	fs.StringVar(&o.pod.UID, "pod-uid", getenv("POD_UID"), "this grant Pod's UID, for -home kubernetes. The downward API fills it through POD_UID")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")
}

// check names every missing part of the identity in one error.
func (p podIdentity) check() error {
	var missing []string
	for _, f := range []struct{ flag, env, value string }{
		{"-pod-name", "POD_NAME", p.Name},
		{"-pod-namespace", "POD_NAMESPACE", p.Namespace},
		{"-pod-uid", "POD_UID", p.UID},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.flag+" ("+f.env+")")
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("-home kubernetes needs the Pod identity, missing %s. The downward API fills each one",
		strings.Join(missing, ", "))
}

// usage prints the form's synopsis, then every flag.
func usage(fs *flag.FlagSet, cmd string) {
	w := fs.Output()
	if cmd == serveCmd {
		_, _ = fmt.Fprint(w, "usage: fiberd [flags]\n       fiberd run [flags] TEMPLATE [args]\n       fiberd healthz [flags]\n       fiberd readyz [flags]\n\n")
	} else {
		_, _ = fmt.Fprintf(w, "usage: fiberd %s [flags]\n\n", cmd)
	}
	fs.PrintDefaults()
}

// parse is buildConfig for run. done is true when run should exit now
// with code, for -h, -version or a usage error.
func (e env) parse(cmd string, args []string, stdout, stderr io.Writer) (o *options, code int, done bool) {
	o, err := buildConfig(cmd, args, e.getenv, stderr)
	var fe flagError
	switch {
	case errors.Is(err, flag.ErrHelp):
		return nil, 0, true
	case errors.As(err, &fe):
		return nil, 2, true
	case err != nil:
		_, _ = fmt.Fprintln(stderr, "fiberd:", err)
		return nil, 2, true
	case o.version:
		_, _ = fmt.Fprintln(stdout, "fiberd", cli.Version(version))
		return nil, 0, true
	}
	return o, 0, false
}

// probe is fiberd healthz and fiberd readyz. It asks the running
// fiberd's admin socket, under -state, for /healthz or /readyz. It
// exits 0 on a 200 and 1 on anything else, a 503 or a socket nobody
// serves, with the reason on stderr.
func (e env) probe(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) int {
	o, code, done := e.parse(cmd, args, stdout, stderr)
	if done {
		return code
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := e.askAdmin(ctx, &o.fiberd, cmd); err != nil {
		log.New(stderr, "", log.LstdFlags).Print(err)
		return 1
	}
	return 0
}

// serveKubernetes runs fiberd in a grant Pod. It logs through klog's
// text logger on stderr, and fiberd's standard-library log lines land
// there in the same format. PrepareMounts and then NarrowCaps run after
// the logger is set and before RunContext, since NarrowCaps re-executes
// the process.
func (e env) serveKubernetes(ctx context.Context, o *options, stderr io.Writer) int {
	logger := textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(stderr)))
	klog.SetLogger(logger)
	klog.CopyStandardLogTo("INFO")
	ctx = klog.NewContext(ctx, logger)
	if err := o.fiberd.PrepareMounts(); err != nil {
		logger.Error(err, "fiberd could not start")
		return 1
	}
	if err := o.fiberd.NarrowCaps(); err != nil {
		logger.Error(err, "fiberd could not start")
		return 1
	}
	if err := e.runKube(ctx, o); err != nil {
		logger.Error(err, "fiberd failed")
		return 1
	}
	return 0
}

// closer is a home that holds something its Run does not end.
type closer interface{ Close() }

// runKube runs fiberd with the kubernetes home and closes the home once
// the run returns, whatever it returned. A run can fail after building
// the home and before starting its Run, and only Close ends what New
// started then.
func (e env) runKube(ctx context.Context, o *options) error {
	var built home.Home
	err := e.runFiberd(ctx, &o.fiberd, e.kubeHome(ctx, o.pod, &built))
	if c, ok := built.(closer); ok {
		c.Close()
	}
	return err
}

// kubeHome is the factory for -home kubernetes. It builds the API client
// when fiberd asks for its home, so a Pod without a service account
// fails the run. ctx carries the logger. NewKube checks it once, and the
// rest.Config timeout bounds discovery. The home it builds lands in
// built, and ctx ending closes it, which cuts EndpointHost's wait short.
func (e env) kubeHome(ctx context.Context, pod podIdentity, built *home.Home) fiberd.HomeFactory {
	return func(c *fiberd.Config, jwks *grant.Cache) (home.Home, error) {
		family, err := c.Family()
		if err != nil {
			return nil, err
		}
		kube, err := e.newKube(ctx)
		if err != nil {
			return nil, fmt.Errorf("kubernetes home: %w", err)
		}
		h, err := e.newHome(kubehome.Config{
			Kube:         kube,
			PodName:      pod.Name,
			PodNamespace: pod.Namespace,
			PodUID:       pod.UID,
			StaleTTL:     c.Node.StaleTTL,
			GrantsDir:    c.Node.GrantsDir,
			Cache:        jwks,
			Family:       family,
			Devices:      c.Node.Devices,
			CgroupRoot:   c.Node.CgroupRoot,
			Logger:       klog.FromContext(ctx),
		})
		if err != nil {
			return nil, err
		}
		*built = h
		if hc, ok := h.(closer); ok {
			context.AfterFunc(ctx, hc.Close)
		}
		return h, nil
	}
}
