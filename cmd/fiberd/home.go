package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"

	"github.com/Azure/fiberd/internal/cli"
	"github.com/Azure/fiberd/pkg/fiberd"
	"github.com/Azure/fiberd/pkg/grant"
	"github.com/Azure/fiberd/pkg/home"
	kubehome "github.com/Azure/fiberd/pkg/home/kubernetes"
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
	// newHome builds the kubernetes home from its config. ctx bounds the
	// build, which is the first grant fetch.
	newHome func(ctx context.Context, cfg kubehome.Config) (home.Home, error)
	// runFiberd runs fiberd with the home the factory builds.
	runFiberd func(ctx context.Context, c *fiberd.Config, newHome fiberd.HomeFactory) error
	// signalCtx derives a context that SIGINT or SIGTERM ends. Its stop
	// unregisters the handler.
	signalCtx func(ctx context.Context) (context.Context, context.CancelFunc)
}

// hostEnv is the real host.
func hostEnv() env {
	return env{getenv: os.Getenv, askAdmin: askAdmin, newKube: inClusterKube, newHome: newKubeHome,
		runFiberd: fiberd.RunContext, signalCtx: notifyStop}
}

// notifyStop is a context that SIGINT or SIGTERM ends.
func notifyStop(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}

// errStoppedBeforeStart marks a home build that a signal ended. It is a
// stop, not a failure.
var errStoppedBeforeStart = errors.New("stopped by a signal before fiberd started")

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
func newKubeHome(ctx context.Context, cfg kubehome.Config) (home.Home, error) {
	h, err := kubehome.New(ctx, cfg)
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
	grant   grantFetch  // -grant-token-file, -grant-ca-file, -grant-fetch-timeout
	version bool        // -version
}

// podIdentity is who a kubernetes home is. A grant Pod learns it from
// the downward API.
type podIdentity struct{ Name, Namespace, UID string }

// grantFetch is how a kubernetes home fetches its own grant from -issuer.
// An empty TokenFile leaves grants to arrive as files only.
type grantFetch struct {
	TokenFile, CAFile string
	Timeout           time.Duration
}

// flagError is a flag error the flag package has already reported.
type flagError struct{ error }

// buildConfig parses args for the form cmd and checks them. Serving with
// -home kubernetes needs the whole Pod identity. Without -node-id the
// Pod name is the node id, so a grant's audience names the Pod. Without
// -cgroup-root the home reads the container's own cgroup. Fetching the
// grant with -grant-token-file needs -issuer and -grants-dir too, and
// -grant-ca-file needs -grant-token-file. The token file's directory is
// hidden from fibers. The probe forms need none of it. -version skips
// the checks.
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
	o.grant.TokenFile = strings.TrimSpace(o.grant.TokenFile)
	o.grant.CAFile = strings.TrimSpace(o.grant.CAFile)
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
		if err := o.grant.check(o.fiberd.Trust.Issuer, o.fiberd.Node.GrantsDir); err != nil {
			return nil, err
		}
		if o.grant.TokenFile != "" {
			// proc fibers run as fiberd's uid, so file modes cannot keep
			// them from the Pod's token. Its directory is hidden instead.
			abs, err := filepath.Abs(o.grant.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("-grant-token-file: %w", err)
			}
			o.fiberd.Runtime.FiberHide = append(o.fiberd.Runtime.FiberHide, filepath.Dir(abs))
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
	fs.StringVar(&o.grant.TokenFile, "grant-token-file", "", "this grant Pod's bound service-account token file, for -home kubernetes. fiberd fetches and renews its own grant from -issuer at /v1/grant with it and writes the grant into -grants-dir. Empty leaves grants to arrive as files only")
	fs.StringVar(&o.grant.CAFile, "grant-ca-file", "", "PEM CA bundle the grant endpoint's certificate must chain to, for -grant-token-file. Empty means the system roots")
	fs.DurationVar(&o.grant.Timeout, "grant-fetch-timeout", kubehome.DefaultGrantFetchTimeout, "how long the start retries the first grant fetch before fiberd refuses to start, for -grant-token-file. A Pod restarting with an unexpired grant file starts anyway")
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

// check names every flag the grant fetch needs and lacks in one error.
// buildConfig has trimmed the file flags. The home's own Validate checks
// the values themselves.
func (g grantFetch) check(issuer, grantsDir string) error {
	if g.TokenFile == "" {
		if g.CAFile != "" {
			return errors.New("-grant-ca-file needs -grant-token-file")
		}
		return nil
	}
	var missing []string
	for _, f := range []struct{ flag, value string }{
		{"-issuer", issuer},
		{"-grants-dir", grantsDir},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.flag)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("-grant-token-file needs -issuer and -grants-dir, missing %s", strings.Join(missing, ", "))
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
// the process. A signal while the home is built, which covers the first
// grant fetch, ends the build with errStoppedBeforeStart. That exits 0,
// as a stop after fiberd serves does.
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
		// A signal during the first grant fetch is a stop, not a failure.
		if errors.Is(err, errStoppedBeforeStart) {
			logger.Info("fiberd stopped before it started", "reason", err.Error())
			return 0
		}
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
	err := e.runFiberd(ctx, &o.fiberd, e.kubeHome(ctx, o.pod, o.grant, &built))
	if c, ok := built.(closer); ok {
		c.Close()
	}
	return err
}

// kubeHome is the factory for -home kubernetes. It builds the API client
// when fiberd asks for its home, so a Pod without a service account
// fails the run. ctx carries the logger. NewKube checks it once, and the
// rest.Config timeout bounds discovery. New runs under a signal context
// derived from ctx, so SIGINT or SIGTERM during the first grant fetch
// ends it at once. RunContext installs its own handler only after the
// factory returns, so nothing else catches a signal then. The build's
// error then wraps errStoppedBeforeStart. The home it builds lands in
// built, and ctx ending closes it, which cuts EndpointHost's wait short.
// The grant fetch reaches the issuer fiberd verifies grants against.
func (e env) kubeHome(ctx context.Context, pod podIdentity, fetch grantFetch, built *home.Home) fiberd.HomeFactory {
	return func(c *fiberd.Config, jwks *grant.Cache) (home.Home, error) {
		family, err := c.Family()
		if err != nil {
			return nil, err
		}
		kube, err := e.newKube(ctx)
		if err != nil {
			return nil, fmt.Errorf("kubernetes home: %w", err)
		}
		sctx, stop := e.signalCtx(ctx)
		h, err := e.newHome(sctx, kubehome.Config{
			Kube:              kube,
			PodName:           pod.Name,
			PodNamespace:      pod.Namespace,
			PodUID:            pod.UID,
			StaleTTL:          c.Node.StaleTTL,
			GrantsDir:         c.Node.GrantsDir,
			GrantTokenFile:    fetch.TokenFile,
			GrantIssuerURL:    c.Trust.Issuer,
			GrantCAFile:       fetch.CAFile,
			GrantFetchTimeout: fetch.Timeout,
			Cache:             jwks,
			Family:            family,
			Devices:           c.Node.Devices,
			CgroupRoot:        c.Node.CgroupRoot,
			Logger:            klog.FromContext(ctx),
		})
		// The handler must not outlive the build. RunContext's own handler
		// drains on SIGTERM. A lingering one here would cancel the run
		// instead of letting it drain. stop cancels sctx too, so whether a
		// signal ended the build is read first.
		signalled := sctx.Err() != nil
		stop()
		if err != nil {
			if signalled {
				return nil, fmt.Errorf("%w: %w", errStoppedBeforeStart, err)
			}
			return nil, err
		}
		*built = h
		if hc, ok := h.(closer); ok {
			context.AfterFunc(ctx, hc.Close)
		}
		return h, nil
	}
}

// Without it a renamed method would let the Kubernetes home self-admit
// any grant naming it.
var _ fiberd.SelfAdmitter = (*kubehome.Home)(nil)
