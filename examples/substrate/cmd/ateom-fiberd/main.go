// ateom-fiberd is a Substrate sandbox-class herder whose actors are
// fibers: one binary that runs fiberd's agent (the substrate home, the
// proc backend, a file delta registry) and, in front of it, the gRPC
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
	// Substrate's worker container arguments (cmd/atecontroller); the
	// egress and CONNECT listeners are accepted and not served: fibers
	// use the Pod's network directly and have one port.
	podUID := flag.String("pod-uid", env("POD_UID", ""), "the worker Pod's uid (Substrate keys the herder by it)")
	listen := flag.String("atunnel-listen-address", ":443", "ingress: where atenet-router connects (mTLS)")
	_ = flag.String("atunnel-connect-listen-address", ":8443", "accepted, not served (CONNECT tunnels)")
	credBundle := flag.String("atunnel-credential-bundle", "", "PEM with this Pod's key and certificate (projected by Substrate)")
	trustBundle := flag.String("atunnel-trust-bundle", "", "PEM with the CAs the router's certificate chains to")
	_ = flag.String("atunnel-egress-listen-address", "", "accepted, not served (egress gateway)")
	_ = flag.String("atunnel-egress-trust-bundle", "", "accepted, unused")
	clientID := flag.String("atunnel-client-identity", ingress.DefaultAllowedClientID, "the SPIFFE id the router presents")
	readyAddr := flag.String("readiness-listen-address", "0.0.0.0:8080", "the kubelet's /readyz")
	basePath := flag.String("base-path", herder.DefaultBase, "the hostPath shared with atelet")
	_ = flag.String("otlp-relay-socket", "", "accepted, unused")
	_ = flag.String("log-level", "", "accepted, unused")
	_ = flag.Bool("version", false, "accepted")
	flag.Parse()
	if *podUID == "" {
		log.Fatal("ateom-fiberd: -pod-uid (or POD_UID) is required")
	}
	if err := run(*podUID, *listen, *credBundle, *trustBundle, *clientID, *readyAddr, herder.Paths{Base: *basePath}); err != nil {
		log.Fatalf("ateom-fiberd: %v", err)
	}
}

func run(podUID, listen, credBundle, trustBundle, clientID, readyAddr string, paths herder.Paths) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// fiberd's side, from the image's environment.
	stateDir := env("ATEOM_FIBERD_STATE", "/var/lib/fiberd")
	agentAddr := env("ATEOM_FIBERD_LISTEN", "127.0.0.1:8484")
	templates := map[string]string{}
	for _, e := range strings.Split(env("ATEOM_FIBERD_TEMPLATE", "default=/usr/local/bin/refzygote --heap-mb 16 --http"), ";") {
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
	h, err := subhome.New(subhome.Config{
		Audience: podUID, IssuerURL: issuerURL, ProbeSocket: paths.SupportSocket(),
		CgroupRoot: os.Getenv("ATEOM_FIBERD_CGROUP_ROOT"),
		Scope:      []core.ScopeClaim{{Name: "worker_pod_uid", Value: podUID}, {Name: "node", Value: os.Getenv("NODE_NAME")}},
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
	c.RuntimeName = env("ATEOM_FIBERD_RUNTIME", "proc")
	c.CRIUBin = env("ATEOM_FIBERD_CRIU", c.CRIUBin)
	c.Templates = templates
	c.RunDir = env("ATEOM_FIBERD_RUN_DIR", "/run/fiberd")
	c.DeltaRegistry = registry
	c.AdminPath = filepath.Join(stateDir, "admin.sock")
	c.Finish()
	agentErr := make(chan error, 1)
	go func() {
		agentErr <- agent.Run(&c, func(*agent.Config, core.Verifier, *grant.Cache) (fhome.Home, error) { return h, nil })
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

	// The herder atelet drives.
	svc := herder.New(herder.Config{
		Client: client, Grants: h, Router: ing, Paths: paths,
		Host: host.Config{DeltaRegistry: registry, HomeID: podUID},
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
	go func() {
		<-ctx.Done()
		svc.Drain()
		gs.GracefulStop()
	}()

	// Readiness for the kubelet: the agent up and every minted template warm.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.Ready() {
			http.Error(w, "warming", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
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
