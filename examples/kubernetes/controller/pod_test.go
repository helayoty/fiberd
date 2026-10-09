package controller_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/controller"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// TestBuildPod checks the grant Pod a CapacityGrant becomes. It pins
// fiberd-k8s as PID 1 with its flags, the node id from the Pod's name, the
// projected grant, the readiness gate, the owner and the security context.
func TestBuildPod(t *testing.T) {
	yes, no := true, false
	privileged := &controller.SecurityContext{Privileged: true}
	measured := &controller.SecurityContext{
		Capabilities:   &controller.Capabilities{Add: []string{"SETPCAP", "NET_ADMIN", "SYS_CHROOT", "SYS_PTRACE", "SYS_ADMIN", "SYS_RESOURCE", "SYS_TIME"}, Drop: []string{"ALL"}},
		SeccompProfile: &controller.SeccompProfile{Type: "Unconfined"}}
	// base is the flags every grant Pod's agent gets, for a 1m lease.
	base := func(runtime, family string) []string {
		return []string{"-verifier", "jwks", "-issuer", issuerURL, "-jwks-max-stale", "1m0s", "-insecure-plaintext",
			"-listen", ":8484", "-runtime", runtime, "-node-id", "$(FIBERD_NODE_ID)",
			"-state", "/var/lib/fiberd", "-run-dir", "/run/fiberd", "-grants-dir", controller.GrantsMount,
			"-endpoint-family", family}
	}
	cases := []struct {
		name   string
		pod    controller.PodSpec
		args   []string
		sa     string
		labels map[string]string
		sc     *controller.SecurityContext
		check  func(t *testing.T, p *controller.Pod)
	}{
		{name: "the defaults: proc, inet4, the fiberd-grant account, measured capabilities",
			pod:  controller.PodSpec{Image: "img"},
			args: base("proc", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: measured},
		{name: "every field set lands in the Pod",
			pod: controller.PodSpec{Image: "img", Runtime: "gvisor", EndpointFamily: "inet6", ServiceAccountName: "sa",
				Devices: []string{"/dev/a", "/dev/b", "/dev/c"}, UnsafeAdmin: true, Args: []string{"-template", "t=/bin/z"},
				Labels: map[string]string{"team": "x"}, Annotations: map[string]string{"note": "y"},
				NodeSelector: map[string]string{"pool": "gpu"}, NodeName: "n1",
				Resources:      json.RawMessage(`{"limits":{"memory":"1Gi"}}`),
				ResourceClaims: json.RawMessage(`[{"name":"gpu","resourceClaimTemplateName":"t"}]`)},
			args: append(base("gvisor", "inet6"), "-devices", "/dev/a,/dev/b,/dev/c", "-admin-unsafe", "-template", "t=/bin/z"),
			sa:   "sa", labels: map[string]string{controller.GrantLabel: "g", "team": "x"}, sc: privileged,
			check: func(t *testing.T, p *controller.Pod) {
				if p.Metadata.Annotations["note"] != "y" || p.Spec.NodeSelector["pool"] != "gpu" || p.Spec.NodeName != "n1" {
					t.Fatalf("placement fields = %+v %+v", p.Metadata, p.Spec)
				}
				if string(p.Spec.Containers[0].Resources) != `{"limits":{"memory":"1Gi"}}` ||
					string(p.Spec.ResourceClaims) != `[{"name":"gpu","resourceClaimTemplateName":"t"}]` {
					t.Fatalf("resources %s, claims %s", p.Spec.Containers[0].Resources, p.Spec.ResourceClaims)
				}
			}},
		{name: "one device is passed as it is",
			pod:  controller.PodSpec{Devices: []string{"/dev/sim0"}},
			args: append(base("proc", "inet4"), "-devices", "/dev/sim0"), sa: "fiberd-grant",
			labels: map[string]string{controller.GrantLabel: "g"}, sc: measured},
		// The spec's labels must not move the Pod out of its grant's
		// Services.
		{name: "the spec cannot relabel the Pod as another grant's",
			pod:  controller.PodSpec{Labels: map[string]string{controller.GrantLabel: "someone-else"}},
			args: base("proc", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: measured},
		{name: "proc, privileged asked for",
			pod:  controller.PodSpec{Runtime: "proc", Privileged: &yes},
			args: base("proc", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: privileged},
		{name: "proc, privileged refused",
			pod:  controller.PodSpec{Runtime: "proc", Privileged: &no},
			args: base("proc", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: measured},
		{name: "an unmeasured runtime runs privileged",
			pod:  controller.PodSpec{Runtime: "runc"},
			args: base("runc", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: privileged},
		{name: "an unmeasured runtime, privileged refused",
			pod:  controller.PodSpec{Runtime: "hyperlight", Privileged: &no},
			args: base("hyperlight", "inet4"), sa: "fiberd-grant", labels: map[string]string{controller.GrantLabel: "g"}, sc: measured},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := &controller.CapacityGrant{}
			cg.Metadata = kube.ObjectMeta{Name: "g", Namespace: "t", UID: "u"}
			cg.Spec.Pod = tc.pod
			p := controller.BuildPod(cg, issuerURL, time.Minute)
			if p.APIVersion != "v1" || p.Kind != "Pod" || p.Metadata.Name != "g-grant" || p.Metadata.Namespace != "t" {
				t.Fatalf("pod identity = %s %s %+v", p.APIVersion, p.Kind, p.Metadata)
			}
			wantOwner := []kube.OwnerReference{{APIVersion: controller.APIVersion, Kind: controller.Kind, Name: "g", UID: "u", Controller: true, BlockOwnerDeletion: true}}
			if !reflect.DeepEqual(p.Metadata.OwnerReferences, wantOwner) {
				t.Fatalf("owner = %+v", p.Metadata.OwnerReferences)
			}
			if !reflect.DeepEqual(p.Metadata.Labels, tc.labels) {
				t.Fatalf("labels = %v, want %v", p.Metadata.Labels, tc.labels)
			}
			if p.Spec.ServiceAccountName != tc.sa || p.Spec.RestartPolicy != "Always" ||
				!reflect.DeepEqual(p.Spec.ReadinessGates, []controller.ReadinessGate{{ConditionType: controller.ReadyCondition}}) {
				t.Fatalf("spec = %+v", p.Spec)
			}
			wantVolumes := []controller.Volume{
				{Name: "grants", Secret: &controller.SecretVolume{SecretName: "g-grant", Optional: true}},
				{Name: "state", EmptyDir: &controller.EmptyDirVolume{}},
				{Name: "run", EmptyDir: &controller.EmptyDirVolume{}},
			}
			if !reflect.DeepEqual(p.Spec.Volumes, wantVolumes) {
				t.Fatalf("volumes = %+v", p.Spec.Volumes)
			}
			if len(p.Spec.Containers) != 1 {
				t.Fatalf("containers = %+v", p.Spec.Containers)
			}
			c := p.Spec.Containers[0]
			if c.Name != "agent" || c.Image != tc.pod.Image || !reflect.DeepEqual(c.Command, []string{"tini", "--", "fiberd-k8s"}) {
				t.Fatalf("container = %s %s %v", c.Name, c.Image, c.Command)
			}
			if !reflect.DeepEqual(c.Args, tc.args) {
				t.Fatalf("args = %q\nwant %q", c.Args, tc.args)
			}
			// -node-id is the Pod's name, because Kubernetes expands
			// $(FIBERD_NODE_ID) in args from this env var.
			if len(c.Env) != 1 || c.Env[0].Name != "FIBERD_NODE_ID" || c.Env[0].ValueFrom.FieldRef.FieldPath != "metadata.name" {
				t.Fatalf("env = %+v", c.Env)
			}
			wantMounts := []controller.VolumeMount{
				{Name: "grants", MountPath: controller.GrantsMount, ReadOnly: true},
				{Name: "state", MountPath: "/var/lib/fiberd"},
				{Name: "run", MountPath: "/run/fiberd"},
			}
			if !reflect.DeepEqual(c.VolumeMounts, wantMounts) {
				t.Fatalf("mounts = %+v", c.VolumeMounts)
			}
			if !reflect.DeepEqual(c.Ports, []controller.ContainerPort{{Name: "grpc", ContainerPort: 8484}}) ||
				!reflect.DeepEqual(c.ReadinessProbe, &controller.Probe{TCPSocket: &controller.TCPSocketAction{Port: 8484}, PeriodSeconds: 2}) {
				t.Fatalf("ports %+v, readiness probe %+v", c.Ports, c.ReadinessProbe)
			}
			// Liveness is the admin socket's /healthz, which a poisoned
			// audit spool turns to 503, so the kubelet restarts the agent.
			healthz := &controller.ExecAction{Command: []string{"fiberd-k8s", "-state", "/var/lib/fiberd", "-healthz"}}
			if !reflect.DeepEqual(c.LivenessProbe, &controller.Probe{Exec: healthz, PeriodSeconds: 10, TimeoutSeconds: 5, FailureThreshold: 3}) ||
				!reflect.DeepEqual(c.StartupProbe, &controller.Probe{Exec: healthz, PeriodSeconds: 2, TimeoutSeconds: 5, FailureThreshold: 60}) {
				t.Fatalf("liveness probe %+v, startup probe %+v", c.LivenessProbe, c.StartupProbe)
			}
			if !reflect.DeepEqual(c.SecurityContext, tc.sc) {
				g, _ := json.Marshal(c.SecurityContext)
				w, _ := json.Marshal(tc.sc)
				t.Fatalf("securityContext = %s, want %s", g, w)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
