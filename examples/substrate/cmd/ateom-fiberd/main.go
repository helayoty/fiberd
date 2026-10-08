// ateom-fiberd is a Substrate sandbox-class herder whose actors are
// fibers: one binary that runs fiberd's agent (the substrate home, the
// gVisor backend, a file delta registry) and, in front of it, the gRPC
// service atelet drives, the mTLS ingress atenet-router dials and the
// readiness endpoint the kubelet probes. It takes the exact arguments
// Substrate's controller gives every worker container, so a WorkerPool
// needs nothing but workerImage pointed at it; what fiberd runs inside
// is configured through the image's environment (ATEOM_FIBERD_*).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/runtime/host"

	"github.com/helayoty/fiberd/examples/substrate/capacity"
	"github.com/helayoty/fiberd/examples/substrate/herder"
	subhome "github.com/helayoty/fiberd/examples/substrate/home"
	"github.com/helayoty/fiberd/examples/substrate/ingress"
	ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	o, err := parseArgs(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := run(o.podUID, o.listen, o.credBundle, o.trustBundle, o.clientID, o.readyAddr, o.paths); err != nil {
		log.Fatalf("ateom-fiberd: %v", err)
	}
}

// options are the worker container's arguments that run uses.
type options struct {
	podUID, listen, credBundle, trustBundle, clientID, readyAddr string
	paths                                                        herder.Paths
}

// parseArgs reads Substrate's worker container arguments
// (cmd/atecontroller) from args into fs. The egress and CONNECT listeners
// are accepted but not served, because fibers use the Pod's network
// directly and have one port.
func parseArgs(fs *flag.FlagSet, args []string) (options, error) {
	podUID := fs.String("pod-uid", env("POD_UID", ""), "the worker Pod's uid (Substrate keys the herder by it)")
	listen := fs.String("atunnel-listen-address", ":443", "ingress: where atenet-router connects (mTLS)")
	_ = fs.String("atunnel-connect-listen-address", ":8443", "accepted, not served (CONNECT tunnels)")
	credBundle := fs.String("atunnel-credential-bundle", "", "PEM with this Pod's key and certificate (projected by Substrate)")
	trustBundle := fs.String("atunnel-trust-bundle", "", "PEM with the CAs the router's certificate chains to")
	_ = fs.String("atunnel-egress-listen-address", "", "accepted, not served (egress gateway)")
	_ = fs.String("atunnel-egress-trust-bundle", "", "accepted, unused")
	clientID := fs.String("atunnel-client-identity", ingress.DefaultAllowedClientID, "the SPIFFE id the router presents")
	readyAddr := fs.String("readiness-listen-address", "0.0.0.0:8080", "the kubelet's /readyz")
	basePath := fs.String("base-path", herder.DefaultBase, "the hostPath shared with atelet")
	_ = fs.String("otlp-relay-socket", "", "accepted, unused")
	_ = fs.String("log-level", "", "accepted, unused")
	_ = fs.Bool("version", false, "accepted")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if *podUID == "" {
		return options{}, errors.New("ateom-fiberd: -pod-uid (or POD_UID) is required")
	}
	return options{podUID: *podUID, listen: *listen, credBundle: *credBundle, trustBundle: *trustBundle,
		clientID: *clientID, readyAddr: *readyAddr, paths: herder.Paths{Base: *basePath}}, nil
}

func run(podUID, listen, credBundle, trustBundle, clientID, readyAddr string, paths herder.Paths) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// fiberd's side, from the image's environment.
	stateDir := env("ATEOM_FIBERD_STATE", "/var/lib/fiberd")
	agentAddr := env("ATEOM_FIBERD_LISTEN", "127.0.0.1:8484")
	templates := map[string]string{}
	for _, e := range strings.Split(env("ATEOM_FIBERD_TEMPLATE", defaultTemplate), ";") {
		if strings.TrimSpace(e) == "" {
			continue
		}
		if err := host.ParseTemplateFlag(templates, e); err != nil {
			return fmt.Errorf("ATEOM_FIBERD_TEMPLATE: %w", err)
		}
	}
	registry := artifact.FileScheme + filepath.Join(stateDir, "registry")

	// The issuer on the loopback: the agent verifies against it.
	il, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	issuerURL := "http://" + il.Addr().String()
	iso, err := core.ParseIsolation(env("ATEOM_FIBERD_ISOLATION", "UNTRUSTED"))
	if err != nil {
		return fmt.Errorf("ATEOM_FIBERD_ISOLATION: %w", err)
	}
	// The shared keys are checked before the home touches any cgroup.
	deltaKey, sealKey, err := sharedDeltaKeys()
	if err != nil {
		return err
	}
	h, err := subhome.New(subhome.Config{
		Audience: podUID, IssuerURL: issuerURL, ProbeSocket: paths.SupportSocket(),
		CgroupRoot: os.Getenv("ATEOM_FIBERD_CGROUP_ROOT"), Isolation: iso,
		Scope: []core.ScopeClaim{{Name: "worker_pod_uid", Value: podUID}, {Name: "node", Value: os.Getenv("NODE_NAME")}},
	})
	if err != nil {
		return err
	}
	go func() {
		srv := &http.Server{Handler: h.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		if err := srv.Serve(il); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("issuer: %v", err)
		}
	}()

	// The agent, as a library.
	var c agent.Config
	c.Bind(flag.NewFlagSet("fiberd", flag.ContinueOnError))
	c.Listen, c.NodeID, c.StateDir = agentAddr, podUID, stateDir
	c.Verifier, c.Issuer = "jwks", issuerURL
	c.InsecurePlaintext = true
	if err := runtimeEnv(&c); err != nil {
		return err
	}
	c.Templates = templates
	c.RunDir = env("ATEOM_FIBERD_RUN_DIR", "/run/fiberd")
	c.DeltaRegistry = registry
	c.DeltaKey, c.DeltaSealKey = deltaKey, sealKey
	c.DeltaTrust = os.Getenv("ATEOM_FIBERD_DELTA_TRUST")
	c.Finish()
	// Load the keys before the agent starts, so a bad key stops the worker
	// before it serves anything.
	deltaKeys, err := c.LoadDeltaKeys()
	if err != nil {
		return err
	}
	agentErr := make(chan error, 1)
	go func() {
		agentErr <- agent.Run(&c, func(*agent.Config, *grant.Cache) (fhome.Home, error) { return h, nil })
	}()
	if err := waitTCP(ctx, agentAddr, 60*time.Second, agentErr); err != nil {
		return fmt.Errorf("agent did not come up: %w", err)
	}
	client, err := consumer.Dial(ctx, agentAddr)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// The ingress atenet-router dials.
	ing, err := ingress.New(ingress.Config{CredentialBundle: credBundle, TrustBundle: trustBundle, AllowedClientID: clientID})
	if err != nil {
		return err
	}
	if il, err := net.Listen("tcp", listen); err == nil {
		go func() {
			if err := ing.Serve(ctx, il); err != nil {
				log.Printf("ingress: %v", err)
			}
		}()
	} else {
		log.Printf("ingress: not listening on %s: %v (actors are reachable only through the herder's tests)", listen, err)
	}

	// The capacity report. Substrate places no actor on a worker until it
	// says what it can host, so a bad bundle stops the worker here.
	report, err := capacity.New(capacity.Config{Socket: paths.SupportSocket(), CredentialBundle: credBundle,
		TrustBundle: trustBundle, Dir: env("ATEOM_FIBERD_CAPACITY_DIR", capacity.Dir)})
	if err != nil {
		return err
	}

	// The herder atelet drives.
	svc := herder.New(herder.Config{
		Client: client, Grants: h, Router: ing, Paths: paths,
		Host: host.Config{DeltaRegistry: registry, DeltaKeys: deltaKeys, HomeID: podUID},
	})
	go svc.Run(ctx)
	if err := os.MkdirAll(paths.AteomDir(podUID), 0o700); err != nil {
		return err
	}
	sock := paths.SocketPath(podUID)
	_ = os.Remove(sock)
	ul, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	gs := grpc.NewServer()
	ateompb.RegisterAteomServer(gs, svc)
	// Reported once atelet's calls can reach the herder: an actor may be
	// placed here as soon as atelet accepts it.
	go func() {
		if err := report.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("capacity: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		svc.Drain()
		gs.GracefulStop()
	}()

	// Readiness for the kubelet: the agent up and every minted template warm.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", readyz(h.Ready, c.Healthz))
	go func() {
		srv := &http.Server{Addr: readyAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("readyz: %v", err)
		}
	}()

	log.Printf("ateom-fiberd: pod %s serving atelet at %s, ingress on %s, agent at %s, templates %v", podUID, sock, listen, agentAddr, templates)
	err = gs.Serve(ul)
	_ = os.Remove(sock)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// readyz is the kubelet's readiness check. It is 503 while a template
// warms, and while the agent's /healthz is not 200, as when its audit
// spool is poisoned. Substrate then places no actor here.
func readyz(ready func() bool, healthz func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ready() {
			http.Error(w, "warming", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := healthz(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	}
}

// defaultTemplate is what every ActorTemplate runs unless
// ATEOM_FIBERD_TEMPLATE names something else: the reference workload as
// a gVisor sandbox's init, serving HTTP, at its path inside the rootfs.
const defaultTemplate = "default=/bin/refzygote --heap-mb 16 --gvisor --http"

// runtimeEnv picks the agent's backend from the image's environment. The
// default is gvisor, so every actor runs behind its own sandbox kernel and
// the pool's `sandboxClass: gvisor` holds. ATEOM_FIBERD_RUNTIME selects
// another backend for tests of the mechanism. A gvisor worker whose
// rootfs is missing refuses to start, since an agent without one would
// serve and never warm a template.
func runtimeEnv(c *agent.Config) error {
	c.RuntimeName = env("ATEOM_FIBERD_RUNTIME", "gvisor")
	c.GvisorRootfs = env("ATEOM_FIBERD_GVISOR_ROOTFS", "/var/lib/fiberd/gvisor-rootfs")
	c.Runsc = env("ATEOM_FIBERD_RUNSC", c.Runsc)
	c.CRIUBin = env("ATEOM_FIBERD_CRIU", c.CRIUBin)
	if c.RuntimeName == "gvisor" {
		if st, err := os.Stat(c.GvisorRootfs); err != nil || !st.IsDir() {
			return fmt.Errorf("ATEOM_FIBERD_GVISOR_ROOTFS: %s is not a directory (the image builds one with hack/gvisor/rootfs.sh)", c.GvisorRootfs)
		}
	}
	return nil
}

// sharedDeltaKeys returns the paths of the delta keys every worker of a
// pool shares. A worker without them refuses to start. Keys it generated
// for itself would keep its snapshots from restoring on any other worker.
func sharedDeltaKeys() (key, seal string, err error) {
	for _, k := range []struct {
		env  string
		path *string
	}{{"ATEOM_FIBERD_DELTA_KEY", &key}, {"ATEOM_FIBERD_DELTA_SEAL_KEY", &seal}} {
		*k.path = os.Getenv(k.env)
		if *k.path == "" {
			return "", "", fmt.Errorf("%s is required, so that every worker shares the pool's delta keys", k.env)
		}
		if _, err := os.Stat(*k.path); err != nil {
			return "", "", fmt.Errorf("%s: %w (mount the pool's shared delta keys there)", k.env, err)
		}
	}
	return key, seal, nil
}

// waitTCP waits for addr to accept connections, or for the agent to fail.
func waitTCP(ctx context.Context, addr string, timeout time.Duration, agentErr <-chan error) error {
	deadline := time.Now().Add(timeout)
	for {
		select {
		case err := <-agentErr:
			if err == nil {
				err = errors.New("agent exited")
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not accepting after %s", addr, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
