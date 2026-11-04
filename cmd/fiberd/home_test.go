package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	kubehome "github.com/helayoty/fiberd/pkg/home/kubernetes"
	"github.com/helayoty/fiberd/pkg/home/kubernetes/fake"
)

// defaultCgroup is -cgroup-root's default.
const defaultCgroup = "/sys/fs/cgroup/fiberd"

// testEnv reads nothing from the host. vars stands in for the
// environment and ask for the admin socket. It builds no client and no
// home and runs no fiberd unless a test replaces newKube, newHome and
// runFiberd.
func testEnv(vars map[string]string, ask func(ctx context.Context, c *fiberd.Config, path string) error) env {
	return env{
		getenv:   func(k string) string { return vars[k] },
		askAdmin: ask,
		newKube: func(context.Context) (kubehome.Kube, error) {
			return nil, errors.New("no cluster in a unit test")
		},
		newHome: func(kubehome.Config) (home.Home, error) {
			return nil, errors.New("no home in a unit test")
		},
		runFiberd: func(context.Context, *fiberd.Config, fiberd.HomeFactory) error {
			return errors.New("no fiberd in a unit test")
		},
	}
}

// TestBuildConfig checks what each form makes of its flags and the
// downward API's variables. Serving with -home kubernetes needs the whole
// Pod identity, names every missing part, and takes the Pod name as the
// node id and the container's own cgroup unless told otherwise. Fetching
// the grant needs -issuer and -grants-dir, names each one missing, and
// hides the token file's directory from fibers. The probes and -home
// standalone take the same flags and check neither the identity nor the
// grant fetch.
func TestBuildConfig(t *testing.T) {
	hostname, _ := os.Hostname()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fetch := []string{"-issuer", "https://issuer.example", "-grants-dir", "/grants"}
	pod := map[string]string{"POD_NAME": "grant-a-0", "POD_NAMESPACE": "tenant", "POD_UID": "uid-1"}
	fromEnv := podIdentity{Name: "grant-a-0", Namespace: "tenant", UID: "uid-1"}
	kube := []string{"-home", "kubernetes"}
	token := []string{"-grant-token-file", "/var/run/secrets/fiberd/token"}
	cases := []struct {
		name string
		cmd  string
		args []string
		env  map[string]string

		wantHome    string
		wantPod     podIdentity
		wantNode    string
		wantCgroup  string
		wantState   string     // checked when set
		wantGrant   grantFetch // the zero value stands for the defaults
		wantHide    []string   // fiberd.Runtime.FiberHide
		wantVersion bool
		// wantErr are parts of the error, none for no error. notErr is a
		// part it must not hold.
		wantErr []string
		notErr  string
	}{
		{name: "standalone by default", cmd: serveCmd,
			wantHome: "standalone", wantNode: hostname, wantCgroup: defaultCgroup},
		{name: "standalone keeps the hostname and its cgroup root beside a Pod identity", cmd: serveCmd, env: pod,
			wantHome: "standalone", wantPod: fromEnv, wantNode: hostname, wantCgroup: defaultCgroup},
		{name: "the Pod identity comes from the downward API", cmd: serveCmd, args: kube, env: pod,
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: ""},
		{name: "the Pod flags beat the environment", cmd: serveCmd, env: pod,
			args:     append(slices.Clone(kube), "-pod-name", "grant-b-1", "-pod-namespace", "other", "-pod-uid", "uid-2"),
			wantHome: "kubernetes", wantPod: podIdentity{Name: "grant-b-1", Namespace: "other", UID: "uid-2"},
			wantNode: "grant-b-1", wantCgroup: ""},
		{name: "-node-id wins over the Pod name", cmd: serveCmd, env: pod, args: append(slices.Clone(kube), "-node-id", "node-x"),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "node-x", wantCgroup: ""},
		{name: "a passed -cgroup-root is kept", cmd: serveCmd, env: pod, args: append(slices.Clone(kube), "-cgroup-root", "/sys/fs/cgroup/pod"),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "/sys/fs/cgroup/pod"},
		{name: "a -cgroup-root passed as its default is kept", cmd: serveCmd, env: pod, args: append(slices.Clone(kube), "-cgroup-root", defaultCgroup),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: defaultCgroup},
		{name: "a missing identity names each flag", cmd: serveCmd, args: kube,
			wantErr: []string{"-pod-name (POD_NAME)", "-pod-namespace (POD_NAMESPACE)", "-pod-uid (POD_UID)"}},
		{name: "a missing UID names only it", cmd: serveCmd, args: kube, env: map[string]string{"POD_NAME": "grant-a-0", "POD_NAMESPACE": "tenant"},
			wantErr: []string{"-pod-uid (POD_UID)"}, notErr: "-pod-name"},
		{name: "a blank Pod name is missing", cmd: serveCmd, args: append(slices.Clone(kube), "-pod-name", " "), env: pod,
			wantErr: []string{"-pod-name (POD_NAME)"}, notErr: "-pod-uid"},
		{name: "an unknown home", cmd: serveCmd, args: []string{"-home", "nomad"},
			wantErr: []string{`-home "nomad" unknown`, "standalone or kubernetes"}},
		{name: "an argument after the flags", cmd: serveCmd, args: []string{"healthz"},
			wantErr: []string{`unexpected argument "healthz"`, "see fiberd -h"}},
		{name: "a probe's stray argument names the probe's help", cmd: healthzCmd, args: []string{"now"},
			wantErr: []string{`unexpected argument "now"`, "see fiberd healthz -h"}},
		{name: "readyz names its own help", cmd: readyzCmd, args: []string{"now"},
			wantErr: []string{"see fiberd readyz -h"}},
		{name: "-version skips the checks", cmd: serveCmd, args: append(slices.Clone(kube), "-version"),
			wantHome: "kubernetes", wantNode: hostname, wantCgroup: defaultCgroup, wantVersion: true},
		{name: "healthz takes the flags and needs no identity", cmd: healthzCmd, args: append(slices.Clone(kube), "-state", "/run/fz"),
			wantHome: "kubernetes", wantNode: hostname, wantCgroup: defaultCgroup, wantState: "/run/fz"},
		{name: "readyz takes the flags and needs no identity", cmd: readyzCmd, args: append(slices.Clone(kube), "-state", "/run/fz"),
			wantHome: "kubernetes", wantNode: hostname, wantCgroup: defaultCgroup, wantState: "/run/fz"},
		{name: "a probe refuses an unknown home too", cmd: readyzCmd, args: []string{"-home", "nomad"},
			wantErr: []string{`-home "nomad" unknown`}},
		{name: "the grant fetch is off by default and its first fetch waits 60s", cmd: serveCmd, args: kube, env: pod,
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "",
			wantGrant: grantFetch{Timeout: 60 * time.Second}},
		{name: "-grant-token-file with -issuer and -grants-dir passes", cmd: serveCmd, env: pod,
			args: append(slices.Clone(kube), "-grant-token-file", "/var/run/secrets/fiberd/token", "-grant-ca-file", "/etc/fiberd/ca.pem",
				"-grant-fetch-timeout", "90s", "-issuer", "https://issuer.example", "-grants-dir", "/grants"),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "",
			wantGrant: grantFetch{TokenFile: "/var/run/secrets/fiberd/token", CAFile: "/etc/fiberd/ca.pem", Timeout: 90 * time.Second},
			wantHide:  []string{"/var/run/secrets/fiberd"}},
		{name: "-grant-token-file hides its directory after -fiber-hide", cmd: serveCmd, env: pod,
			args:     slices.Concat(kube, token, fetch, []string{"-fiber-hide", "/srv/extra"}),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "",
			wantGrant: grantFetch{TokenFile: "/var/run/secrets/fiberd/token", Timeout: kubehome.DefaultGrantFetchTimeout},
			wantHide:  []string{"/srv/extra", "/var/run/secrets/fiberd"}},
		{name: "a relative -grant-token-file hides its absolute directory", cmd: serveCmd, env: pod,
			args:     slices.Concat(kube, []string{"-grant-token-file", "secrets/token"}, fetch),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "",
			wantGrant: grantFetch{TokenFile: "secrets/token", Timeout: kubehome.DefaultGrantFetchTimeout},
			wantHide:  []string{filepath.Join(wd, "secrets")}},
		{name: "a blank -grant-token-file is unset", cmd: serveCmd, env: pod,
			args:     append(slices.Clone(kube), "-grant-token-file", " "),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: ""},
		{name: "-grant-token-file and -grant-ca-file lose their spaces", cmd: serveCmd, env: pod,
			args:     slices.Concat(kube, []string{"-grant-token-file", " /var/run/secrets/fiberd/token ", "-grant-ca-file", " /etc/fiberd/ca.pem "}, fetch),
			wantHome: "kubernetes", wantPod: fromEnv, wantNode: "grant-a-0", wantCgroup: "",
			wantGrant: grantFetch{TokenFile: "/var/run/secrets/fiberd/token", CAFile: "/etc/fiberd/ca.pem", Timeout: kubehome.DefaultGrantFetchTimeout},
			wantHide:  []string{"/var/run/secrets/fiberd"}},
		{name: "-grant-token-file without -issuer names it", cmd: serveCmd, env: pod,
			args:    append(slices.Concat(kube, token), "-grants-dir", "/grants"),
			wantErr: []string{"-grant-token-file needs -issuer and -grants-dir, missing -issuer"}, notErr: "missing -issuer, -grants-dir"},
		{name: "-grant-token-file without -grants-dir names it", cmd: serveCmd, env: pod,
			args:    append(slices.Concat(kube, token), "-issuer", "https://issuer.example"),
			wantErr: []string{"-grant-token-file needs -issuer and -grants-dir, missing -grants-dir"}, notErr: "missing -issuer"},
		{name: "-grant-token-file without either names both", cmd: serveCmd, env: pod, args: slices.Concat(kube, token),
			wantErr: []string{"missing -issuer, -grants-dir"}},
		{name: "-grant-ca-file alone names -grant-token-file", cmd: serveCmd, env: pod,
			args:    append(slices.Clone(kube), "-grant-ca-file", "/etc/fiberd/ca.pem"),
			wantErr: []string{"-grant-ca-file needs -grant-token-file"}},
		{name: "a probe ignores the grant flags", cmd: healthzCmd, args: slices.Concat(kube, token),
			wantHome: "kubernetes", wantNode: hostname, wantCgroup: defaultCgroup,
			wantGrant: grantFetch{TokenFile: "/var/run/secrets/fiberd/token", Timeout: kubehome.DefaultGrantFetchTimeout}},
		{name: "standalone ignores the grant flags", cmd: serveCmd, args: token,
			wantHome: "standalone", wantNode: hostname, wantCgroup: defaultCgroup,
			wantGrant: grantFetch{TokenFile: "/var/run/secrets/fiberd/token", Timeout: kubehome.DefaultGrantFetchTimeout}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := buildConfig(tc.cmd, tc.args, func(k string) string { return tc.env[k] }, io.Discard)
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("buildConfig = nil, want an error with %q", tc.wantErr)
				}
				for _, w := range tc.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Fatalf("buildConfig = %q, want it to hold %q", err, w)
					}
				}
				if tc.notErr != "" && strings.Contains(err.Error(), tc.notErr) {
					t.Fatalf("buildConfig = %q, want it without %q", err, tc.notErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildConfig = %v", err)
			}
			if o.home != tc.wantHome || o.pod != tc.wantPod || o.version != tc.wantVersion {
				t.Fatalf("home %q pod %+v version %v, want %q %+v %v", o.home, o.pod, o.version, tc.wantHome, tc.wantPod, tc.wantVersion)
			}
			if o.fiberd.Node.ID != tc.wantNode || o.fiberd.Node.CgroupRoot != tc.wantCgroup {
				t.Fatalf("node id %q cgroup root %q, want %q %q", o.fiberd.Node.ID, o.fiberd.Node.CgroupRoot, tc.wantNode, tc.wantCgroup)
			}
			if tc.wantState != "" && o.fiberd.Node.StateDir != tc.wantState {
				t.Fatalf("state %q, want %q", o.fiberd.Node.StateDir, tc.wantState)
			}
			wantGrant := tc.wantGrant
			if wantGrant == (grantFetch{}) {
				wantGrant = grantFetch{Timeout: kubehome.DefaultGrantFetchTimeout}
			}
			if o.grant != wantGrant {
				t.Fatalf("grant fetch %+v, want %+v", o.grant, wantGrant)
			}
			if !slices.Equal(o.fiberd.Runtime.FiberHide, tc.wantHide) {
				t.Fatalf("fiber hide %q, want %q", o.fiberd.Runtime.FiberHide, tc.wantHide)
			}
		})
	}
}

// TestRunExitCodes checks the exit codes of every form that stops
// before serving. healthz and readyz ask the admin socket once, inside
// the probe timeout, and exit 0 on a 200 and 1 on anything else.
func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// sick makes the admin socket answer 503.
		sick       bool
		wantCode   int
		wantAsked  string // the path asked for, empty when nothing is
		wantState  string // the -state the probe used, checked when set
		wantStdout string
		wantStderr []string
	}{
		{name: "-version", args: []string{"-version"}, wantCode: 0, wantStdout: "fiberd "},
		{name: "-h prints the forms and the flags", args: []string{"-h"}, wantCode: 0,
			wantStderr: []string{"usage: fiberd [flags]", "fiberd healthz [flags]", "fiberd readyz [flags]", "-home", "-pod-name", "-grant-token-file", "-verifier"}},
		{name: "a bad flag", args: []string{"-nope"}, wantCode: 2, wantStderr: []string{"flag provided but not defined: -nope"}},
		{name: "an unknown home", args: []string{"-home", "nomad"}, wantCode: 2, wantStderr: []string{`-home "nomad" unknown`}},
		{name: "kubernetes with an incomplete identity", args: []string{"-home", "kubernetes", "-pod-name", "grant-a-0"}, wantCode: 2,
			wantStderr: []string{"-pod-namespace (POD_NAMESPACE), -pod-uid (POD_UID)"}},
		{name: "kubernetes fetching its grant without -issuer", wantCode: 2,
			args: []string{"-home", "kubernetes", "-pod-name", "grant-a-0", "-pod-namespace", "tenant", "-pod-uid", "uid-1",
				"-grant-token-file", "/var/run/secrets/fiberd/token", "-grants-dir", "/grants"},
			wantStderr: []string{"fiberd: -grant-token-file needs -issuer and -grants-dir, missing -issuer"}},
		{name: "healthz on a healthy fiberd", args: []string{"healthz", "-state", "/run/fz"}, wantCode: 0,
			wantAsked: "healthz", wantState: "/run/fz"},
		{name: "healthz on a sick fiberd", args: []string{"healthz"}, sick: true, wantCode: 1,
			wantAsked: "healthz", wantStderr: []string{"healthz: 503"}},
		{name: "readyz on a ready fiberd", args: []string{"readyz", "-state", "/run/fz"}, wantCode: 0,
			wantAsked: "readyz", wantState: "/run/fz"},
		{name: "readyz while fiberd drains", args: []string{"readyz"}, sick: true, wantCode: 1,
			wantAsked: "readyz", wantStderr: []string{"readyz: 503", `"draining":true`}},
		{name: "healthz needs no Pod identity", args: []string{"healthz", "-home", "kubernetes"}, wantCode: 0, wantAsked: "healthz"},
		{name: "readyz needs no Pod identity", args: []string{"readyz", "-home", "kubernetes"}, wantCode: 0, wantAsked: "readyz"},
		{name: "healthz -h", args: []string{"healthz", "-h"}, wantCode: 0, wantStderr: []string{"usage: fiberd healthz [flags]", "-state"}},
		{name: "readyz with a bad flag", args: []string{"readyz", "-nope"}, wantCode: 2,
			wantStderr: []string{"flag provided but not defined: -nope"}},
		{name: "readyz with an unknown home", args: []string{"readyz", "-home", "nomad"}, wantCode: 2,
			wantStderr: []string{`-home "nomad" unknown`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			var state string
			e := testEnv(nil, func(ctx context.Context, c *fiberd.Config, path string) error {
				asked = append(asked, path)
				state = c.Node.StateDir
				if d, ok := ctx.Deadline(); !ok || time.Until(d) > probeTimeout {
					t.Errorf("probe deadline %v (set %v), want one within %v", d, ok, probeTimeout)
				}
				if tc.sick {
					return fmt.Errorf(`%s: 503 Service Unavailable: {"audit":"ok","draining":true}`, path)
				}
				return nil
			})
			var stdout, stderr bytes.Buffer
			code := e.run(context.Background(), tc.args, &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("run = %d, want %d: %s", code, tc.wantCode, stderr.String())
			}
			var want []string
			if tc.wantAsked != "" {
				want = []string{tc.wantAsked}
			}
			if !slices.Equal(asked, want) {
				t.Fatalf("asked the admin socket for %q, want %q", asked, want)
			}
			if tc.wantState != "" && state != tc.wantState {
				t.Fatalf("probe used -state %q, want %q", state, tc.wantState)
			}
			if !strings.HasPrefix(stdout.String(), tc.wantStdout) {
				t.Fatalf("stdout %q, want it to start with %q", stdout.String(), tc.wantStdout)
			}
			for _, w := range tc.wantStderr {
				if !strings.Contains(stderr.String(), w) {
					t.Fatalf("stderr %q, want it to hold %q", stderr.String(), w)
				}
			}
		})
	}
}

// TestHomeFactory checks the kubernetes home fiberd builds. It gets the
// Pod identity, fiberd's stale TTL, grants dir, devices and endpoint
// family, the grant fetch flags with -issuer, the key cache fiberd hands
// the factory, and the client the Kube constructor built. A
// constructor's error surfaces.
func TestHomeFactory(t *testing.T) {
	podArgs := []string{"-home", "kubernetes", "-pod-name", "grant-a-0", "-pod-namespace", "tenant", "-pod-uid", "uid-1"}
	jwks := &grant.Cache{}
	cases := []struct {
		name    string
		args    []string
		jwks    *grant.Cache
		kubeErr error
		homeErr error
		want    kubehome.Config // Kube, Clock and Logger are not compared
		wantErr string
	}{
		{name: "the home gets the Pod, the flags and the key cache", jwks: jwks,
			args: []string{"-stale-ttl", "45s", "-grants-dir", "/grants", "-devices", "nvidia0,nvidia1",
				"-endpoint-family", "inet4", "-cgroup-root", "/sys/fs/cgroup/pod"},
			want: kubehome.Config{PodName: "grant-a-0", PodNamespace: "tenant", PodUID: "uid-1",
				StaleTTL: 45 * time.Second, GrantsDir: "/grants", Cache: jwks, Family: endpoint.Inet4,
				Devices: []string{"nvidia0", "nvidia1"}, CgroupRoot: "/sys/fs/cgroup/pod",
				GrantFetchTimeout: kubehome.DefaultGrantFetchTimeout}},
		{name: "the defaults read the container's own cgroup",
			want: kubehome.Config{PodName: "grant-a-0", PodNamespace: "tenant", PodUID: "uid-1",
				StaleTTL: 30 * time.Second, Family: endpoint.Unix, GrantFetchTimeout: kubehome.DefaultGrantFetchTimeout}},
		{name: "the home fetches its grant from -issuer with the grant flags",
			args: []string{"-issuer", "https://issuer.example", "-grants-dir", "/grants", "-grant-token-file", "/var/run/secrets/fiberd/token",
				"-grant-ca-file", "/etc/fiberd/ca.pem", "-grant-fetch-timeout", "90s"},
			want: kubehome.Config{PodName: "grant-a-0", PodNamespace: "tenant", PodUID: "uid-1",
				StaleTTL: 30 * time.Second, GrantsDir: "/grants", Family: endpoint.Unix,
				GrantTokenFile: "/var/run/secrets/fiberd/token", GrantIssuerURL: "https://issuer.example",
				GrantCAFile: "/etc/fiberd/ca.pem", GrantFetchTimeout: 90 * time.Second}},
		{name: "a Kube constructor error surfaces", kubeErr: errors.New("no service account"),
			wantErr: "kubernetes home: no service account"},
		{name: "a home constructor error surfaces", homeErr: errors.New("pod has no uid"),
			wantErr: "pod has no uid"},
		{name: "a bad endpoint family", args: []string{"-endpoint-family", "ipx"},
			wantErr: `endpoint family "ipx"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := buildConfig(serveCmd, append(slices.Clone(podArgs), tc.args...), func(string) string { return "" }, io.Discard)
			if err != nil {
				t.Fatalf("buildConfig = %v", err)
			}
			kube := fake.New("tenant")
			var got *kubehome.Config
			e := testEnv(nil, nil)
			e.newKube = func(context.Context) (kubehome.Kube, error) {
				if tc.kubeErr != nil {
					return nil, tc.kubeErr
				}
				return kube, nil
			}
			e.newHome = func(cfg kubehome.Config) (home.Home, error) {
				got = &cfg
				return nil, tc.homeErr
			}
			var built home.Home
			_, err = e.kubeHome(context.Background(), o.pod, o.grant, &built)(&o.fiberd, tc.jwks)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("factory = %v, want an error with %q", err, tc.wantErr)
				}
				if tc.homeErr == nil && got != nil {
					t.Fatalf("the home was built after a failure: %+v", *got)
				}
				return
			}
			if err != nil {
				t.Fatalf("factory = %v", err)
			}
			if got == nil {
				t.Fatal("the home was never built")
			}
			if got.Kube != kubehome.Kube(kube) {
				t.Fatalf("home Kube %v, want the constructor's client", got.Kube)
			}
			w := tc.want
			if got.PodName != w.PodName || got.PodNamespace != w.PodNamespace || got.PodUID != w.PodUID {
				t.Fatalf("home Pod %q/%q uid %q, want %q/%q uid %q", got.PodNamespace, got.PodName, got.PodUID, w.PodNamespace, w.PodName, w.PodUID)
			}
			if got.StaleTTL != w.StaleTTL || got.GrantsDir != w.GrantsDir || got.Cache != w.Cache || got.Family != w.Family {
				t.Fatalf("home stale TTL %v grants dir %q cache %p family %q, want %v %q %p %q",
					got.StaleTTL, got.GrantsDir, got.Cache, got.Family, w.StaleTTL, w.GrantsDir, w.Cache, w.Family)
			}
			if !slices.Equal(got.Devices, w.Devices) || got.CgroupRoot != w.CgroupRoot {
				t.Fatalf("home devices %q cgroup root %q, want %q %q", got.Devices, got.CgroupRoot, w.Devices, w.CgroupRoot)
			}
			if got.GrantTokenFile != w.GrantTokenFile || got.GrantIssuerURL != w.GrantIssuerURL ||
				got.GrantCAFile != w.GrantCAFile || got.GrantFetchTimeout != w.GrantFetchTimeout {
				t.Fatalf("home grant token file %q issuer %q CA file %q fetch timeout %v, want %q %q %q %v",
					got.GrantTokenFile, got.GrantIssuerURL, got.GrantCAFile, got.GrantFetchTimeout,
					w.GrantTokenFile, w.GrantIssuerURL, w.GrantCAFile, w.GrantFetchTimeout)
			}
		})
	}
}

// closingHome is a home that counts its Close calls. Its other methods
// are never called.
type closingHome struct {
	home.Home
	closes atomic.Int32
	once   sync.Once
	closed chan struct{}
}

func (h *closingHome) Close() {
	h.closes.Add(1)
	h.once.Do(func() { close(h.closed) })
}

// TestRunKubeClosesTheHome checks that the kubernetes home is closed
// once fiberd's run returns, whether it failed or not, and not while it
// runs. A cancelled run context closes it at once, which is what cuts
// EndpointHost's wait short. A home never built is never closed.
func TestRunKubeClosesTheHome(t *testing.T) {
	podArgs := []string{"-home", "kubernetes", "-pod-name", "grant-a-0", "-pod-namespace", "tenant", "-pod-uid", "uid-1"}
	cases := []struct {
		name    string
		runErr  error
		homeErr error
		// cancel ends the run context while fiberd runs.
		cancel     bool
		wantClosed bool
		wantErr    string
	}{
		{name: "a run that fails after building the home closes it",
			runErr:     errors.New("-endpoint-family inet4: home kubernetes has no address of that family"),
			wantClosed: true, wantErr: "no address of that family"},
		{name: "a clean run closes the home", wantClosed: true},
		{name: "a cancelled run context closes the home before the run returns", cancel: true, wantClosed: true},
		{name: "a home never built is never closed", homeErr: errors.New("pod has no uid"), wantErr: "pod has no uid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := buildConfig(serveCmd, podArgs, func(string) string { return "" }, io.Discard)
			if err != nil {
				t.Fatalf("buildConfig = %v", err)
			}
			h := &closingHome{closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := testEnv(nil, nil)
			e.newKube = func(context.Context) (kubehome.Kube, error) { return fake.New("tenant"), nil }
			e.newHome = func(kubehome.Config) (home.Home, error) {
				if tc.homeErr != nil {
					return nil, tc.homeErr
				}
				return h, nil
			}
			e.runFiberd = func(ctx context.Context, c *fiberd.Config, newHome fiberd.HomeFactory) error {
				if _, err := newHome(c, nil); err != nil {
					return err
				}
				if tc.cancel {
					cancel()
					select {
					case <-h.closed:
					case <-time.After(5 * time.Second):
						return errors.New("the cancelled run context never closed the home")
					}
					return tc.runErr
				}
				if n := h.closes.Load(); n != 0 {
					return fmt.Errorf("the home was closed %d times while fiberd ran", n)
				}
				return tc.runErr
			}
			err = e.runKube(ctx, o)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("runKube = %v, want an error with %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runKube = %v", err)
			}
			if n := h.closes.Load(); (n > 0) != tc.wantClosed {
				t.Fatalf("the home was closed %d times after the run, want closed %v", n, tc.wantClosed)
			}
		})
	}
}
