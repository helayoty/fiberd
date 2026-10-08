// Command compare runs one system of the activation benchmark and
// writes JSON lines. One invocation per system, so every system sees the
// same client, the same clock and the same protocol. summarize reads the
// files afterwards.
//
//	compare -adapter pod -system pod-runc-warm -class shared-kernel \
//	    -kube http://127.0.0.1:8001 -image localhost:5002/counter:latest -node compare-control-plane \
//	    -runs 3 -bursts 1,10,50 -out pod-runc-warm.jsonl
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"

	"github.com/helayoty/fiberd/bench/compare"
	"github.com/helayoty/fiberd/bench/compare/adapters/agentsandbox"
	"github.com/helayoty/fiberd/bench/compare/adapters/fiberd"
	"github.com/helayoty/fiberd/bench/compare/adapters/firecracker"
	"github.com/helayoty/fiberd/bench/compare/adapters/pod"
	"github.com/helayoty/fiberd/bench/compare/promtext"
)

type opts struct {
	adapter, system, class, out string
	runs                        int
	bursts                      string
	poll, timeout, idle         time.Duration
	resume                      bool
	density                     int

	// Kubernetes, shared by pod and agentsandbox.
	kubeURL, namespace, image, node, cpu, memory, cgroupRoot string
	runtimeClass, pull, coldCmd                              string
	replicas                                                 int

	// fiberd.
	target, issuerKey, issuerURL, nodeID, digest, isolation, framing, wantScheme string
	wBudget                                                                      uint64
	fiberMax                                                                     int

	// firecracker.
	fcBin, kernel, rootfs, snapshotDir, workDir, netns, uffd string
	vcpu, memMiB                                             int

	// control plane.
	apiserverMetrics, schedulerMetrics, auditLog, tokenFile string
}

func main() {
	var o opts
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	fs.StringVar(&o.adapter, "adapter", "", "pod | agentsandbox | fiberd | firecracker")
	fs.StringVar(&o.system, "system", "", "row name in the table (pod-runc-warm, fiberd-proc, ...)")
	fs.StringVar(&o.class, "class", "", "isolation class: shared-kernel | sandboxed | microvm")
	fs.StringVar(&o.out, "out", "", "JSON lines file (default stdout)")
	fs.IntVar(&o.runs, "runs", 3, "timed runs after the discarded cold run")
	fs.StringVar(&o.bursts, "bursts", "1,10,50", "concurrent activations per run, comma separated")
	fs.DurationVar(&o.poll, "poll", time.Millisecond, "ready poll interval, the quantization bound")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Minute, "one activation's budget to first byte")
	fs.BoolVar(&o.resume, "resume", false, "also time park and resume once per run")
	fs.IntVar(&o.density, "density", 0, "hold this many idle instances per run and read their memory (0 skips)")
	fs.DurationVar(&o.idle, "idle", 30*time.Second, "how long density instances idle before the read")

	fs.StringVar(&o.kubeURL, "kube", "", "API server URL (a kubectl proxy); empty uses the in-cluster service account")
	fs.StringVar(&o.namespace, "namespace", "default", "namespace for Pods and claims")
	fs.StringVar(&o.image, "image", "", "the counter image")
	fs.StringVar(&o.node, "node", "", "nodeName every Pod is pinned to")
	fs.StringVar(&o.cpu, "cpu", "250m", "per-instance CPU limit")
	fs.StringVar(&o.memory, "memory", "64Mi", "per-instance memory limit")
	fs.StringVar(&o.cgroupRoot, "cgroup-root", "", "cgroup v2 root for density (the node's, mounted into the client Pod, or the home's)")
	fs.StringVar(&o.runtimeClass, "runtime-class", "", "pod, agentsandbox: RuntimeClass (gvisor)")
	fs.StringVar(&o.pull, "pull", "IfNotPresent", "pod: imagePullPolicy (Always for the cold case)")
	fs.StringVar(&o.coldCmd, "cold-cmd", "", "pod: command run before every activation to drop the image from the node")
	fs.IntVar(&o.replicas, "replicas", 1, "agentsandbox: warm pool size")

	fs.StringVar(&o.target, "target", "", "fiberd: Fibers service address (plaintext)")
	fs.StringVar(&o.issuerKey, "issuer-key", "", "fiberd: private JWK to mint the grant with")
	fs.StringVar(&o.issuerURL, "issuer", "", "fiberd: issuer URL the home verifies against")
	fs.StringVar(&o.nodeID, "node-id", "", "fiberd: the home's node id (grant audience)")
	fs.StringVar(&o.digest, "template", "sha256:compare", "fiberd: template digest")
	fs.StringVar(&o.isolation, "isolation", "TRUSTED", "fiberd: TRUSTED or UNTRUSTED")
	fs.Uint64Var(&o.wBudget, "w-budget", 64<<20, "fiberd: per-fiber working set ceiling in bytes")
	fs.IntVar(&o.fiberMax, "fiber-max", 0, "fiberd: fibers.max (0 = unlimited)")
	fs.StringVar(&o.framing, "framing", "http", "fiberd: http or line (Hyperlight speaks line only)")
	fs.StringVar(&o.wantScheme, "want-scheme", "", "fiberd: refuse endpoints of another scheme (tcp gates the gVisor row on the relay)")

	fs.StringVar(&o.fcBin, "firecracker", "firecracker", "firecracker: binary")
	fs.StringVar(&o.kernel, "kernel", "", "firecracker: guest kernel")
	fs.StringVar(&o.rootfs, "rootfs", "", "firecracker: ext4 rootfs with /counter")
	fs.StringVar(&o.snapshotDir, "snapshot-dir", "", "firecracker: where the warm snapshot lives")
	fs.StringVar(&o.workDir, "work-dir", "", "firecracker: sockets and park directories")
	fs.StringVar(&o.netns, "netns", "", "firecracker: netns.sh")
	fs.StringVar(&o.uffd, "uffd-handler", "", "firecracker: UFFD page-fault handler binary (the labelled variant)")
	fs.IntVar(&o.vcpu, "vcpu", 1, "firecracker: vCPUs")
	fs.IntVar(&o.memMiB, "mem-mib", 64, "firecracker: guest memory")

	fs.StringVar(&o.apiserverMetrics, "apiserver-metrics", "", "control plane: API server /metrics URL")
	fs.StringVar(&o.schedulerMetrics, "scheduler-metrics", "", "control plane: scheduler /metrics URL")
	fs.StringVar(&o.auditLog, "audit-log", "", "control plane: audit log file")
	fs.StringVar(&o.tokenFile, "token-file", "", "control plane: bearer token for the metrics URLs (default the service account's)")
	_ = fs.Parse(os.Args[1:])
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "compare:", err)
		os.Exit(1)
	}
}

func run(o opts) error {
	if o.adapter == "" || o.system == "" || o.class == "" {
		return fmt.Errorf("need -adapter, -system and -class")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bursts, err := parseBursts(o.bursts)
	if err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	if o.out != "" {
		f, err := os.Create(o.out)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	ad, err := build(ctx, o)
	if err != nil {
		return err
	}
	r := &compare.Runner{Adapter: ad, System: o.system, Class: o.class, Runs: o.runs, Bursts: bursts,
		Poll: o.poll, Timeout: o.timeout, Resume: o.resume, Density: o.density, Idle: o.idle, Out: out, Log: os.Stderr}
	if o.apiserverMetrics != "" || o.schedulerMetrics != "" || o.auditLog != "" {
		r.ControlPlane = sampler(o)
	}
	return r.Run(ctx)
}

func parseBursts(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("-bursts: bad value %q", f)
		}
		out = append(out, n)
	}
	return out, nil
}

func kubeClient(o opts) (*kube.Client, error) {
	if o.kubeURL != "" {
		return &kube.Client{Base: o.kubeURL, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
	}
	return kube.InCluster()
}

func build(ctx context.Context, o opts) (compare.Adapter, error) {
	switch o.adapter {
	case "pod":
		kc, err := kubeClient(o)
		if err != nil {
			return nil, err
		}
		po := pod.Options{Kube: kc, Namespace: o.namespace, Image: o.image, PullPolicy: o.pull, RuntimeClass: o.runtimeClass,
			NodeName: o.node, CPU: o.cpu, Memory: o.memory, CgroupRoot: o.cgroupRoot, Poll: o.poll, Prefix: o.system}
		if o.coldCmd != "" {
			po.RemoveImage = pod.Command(o.coldCmd)
		}
		return pod.New(po)
	case "agentsandbox":
		kc, err := kubeClient(o)
		if err != nil {
			return nil, err
		}
		return agentsandbox.New(agentsandbox.Options{Kube: kc, Namespace: o.namespace, Name: o.system, Image: o.image,
			Replicas: o.replicas, RuntimeClass: o.runtimeClass, NodeName: o.node, CPU: o.cpu, Memory: o.memory,
			CgroupRoot: o.cgroupRoot, Poll: o.poll})
	case "fiberd":
		return fiberd.New(ctx, fiberd.Options{Target: o.target, IssuerKey: o.issuerKey, IssuerURL: o.issuerURL, NodeID: o.nodeID,
			TemplateDigest: o.digest, Isolation: o.isolation, WBudget: o.wBudget, FiberMax: o.fiberMax,
			Framing: compare.Framing(o.framing), WantScheme: o.wantScheme, CgroupRoot: o.cgroupRoot, Poll: o.poll})
	case "firecracker":
		return firecracker.New(firecracker.Options{Binary: o.fcBin, Kernel: o.kernel, Rootfs: o.rootfs, SnapshotDir: o.snapshotDir,
			WorkDir: o.workDir, Netns: o.netns, UFFDHandler: o.uffd, VCPU: o.vcpu, MemMiB: o.memMiB, Poll: o.poll})
	}
	return nil, fmt.Errorf("unknown adapter %q", o.adapter)
}

// sampler wires the control-plane counters docs/design/compare.md lists.
func sampler(o opts) *promtext.Sampler {
	token := ""
	tf := o.tokenFile
	if tf == "" {
		tf = kube.TokenFile
	}
	if b, err := os.ReadFile(tf); err == nil {
		token = strings.TrimSpace(string(b))
	}
	s := &promtext.Sampler{}
	if o.apiserverMetrics != "" {
		f := promtext.Fetch(nil, o.apiserverMetrics, token)
		s.Sources = append(s.Sources,
			promtext.Metric("apiserver_writes", f, "apiserver_request_total", promtext.Writes),
			promtext.Metric("apiserver_objects", f, "apiserver_storage_objects", nil))
	}
	if o.schedulerMetrics != "" {
		f := promtext.Fetch(nil, o.schedulerMetrics, token)
		s.Sources = append(s.Sources, promtext.Metric("scheduler_attempts", f, "scheduler_schedule_attempts_total", nil))
	}
	if o.auditLog != "" {
		s.Sources = append(s.Sources, promtext.AuditLines("audit_events", o.auditLog))
	}
	return s
}
