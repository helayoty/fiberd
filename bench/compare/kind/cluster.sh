#!/usr/bin/env bash
# The "compare" kind cluster of docs/design/compare.md, and nothing
# else: its own registry container, API server audit logging at level
# Metadata, the scheduler's /metrics open to the client, runsc and its
# shim on the node with a "gvisor" RuntimeClass. It never touches
# another cluster.
#
# The registry serves two things. The node pulls the counter image from
# it as localhost:5002 (containerd's hosts.toml below). The grant Pods
# pull their zygote artifacts from it over the kind network, by the
# registry container's address there, which `registry-addr` prints.
#
#   bench/compare/kind/cluster.sh up             create (idempotent)
#   bench/compare/kind/cluster.sh registry-addr  host:port of the registry on the kind network
#   bench/compare/kind/cluster.sh down           delete the cluster and the registry
set -euo pipefail
cd "$(dirname "$0")/../../.."
CLUSTER=${COMPARE_CLUSTER:-compare}
REG_NAME=${COMPARE_REGISTRY:-compare-registry}
REG_PORT=${COMPARE_REGISTRY_PORT:-5002}
RUNSC_RELEASE=${RUNSC_RELEASE:-20260817.0}
# Each binary's sha512, copied from gVisor's .sha512 files for the
# release above (runsc's as docker/criu/Dockerfile pins them), so a
# changed download fails instead of being checked against itself.
RUNSC_SHA512_X86_64=84936438d583ec976800f464e75a83e1515f0890b451b9b4db219c4472b54ca9b106a6772ee683f1e64cce2128871d7637b14d800591f8451b8137f6c39fb2ef
RUNSC_SHA512_AARCH64=6394fd161a4af0dc9a2c29f75c3016d05275a55744f124e12023fa7666a9f161c68d6ce3803ad49205c6a7b5bee0ad2ccf48edff340db344fdafec678c788aa4
SHIM_SHA512_X86_64=b60d1c418b841ab046951cc7a91f490a221198fbe81ec55dc364432578fddd44e97063793ce6651be397af2f64ec47170dff77a45db277819c3fb08fec9f3ced
SHIM_SHA512_AARCH64=a7c0147f635938225e41c9660b95ba5235121a142c11830794e2a52b472783547e2b089bdba4f1344d30f65aeee651b377a1cafadd262a134f5e1ac10c6bf4bb
STATE=${COMPARE_STATE:-$PWD/bin/compare-state}
# kind v0.30.0's node image. Its containerd 2.1.3 replaces 2.1.1, which
# segfaulted under bursts of Pods.
NODE_IMAGE=kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a
NODE="$CLUSTER-control-plane"
KC=(kubectl --context "kind-$CLUSTER")

registry_up() {
  if [ "$(docker inspect -f '{{.State.Running}}' "$REG_NAME" 2>/dev/null)" != true ]; then
    docker run -d --restart=always -p "127.0.0.1:$REG_PORT:5000" --network bridge --name "$REG_NAME" registry:2 >/dev/null
  fi
}

# registry_join puts the registry on the kind network, which exists only
# once kind has made a cluster. On a fresh host that is after cluster_up.
registry_join() {
  if [ -z "$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}x{{end}}' "$REG_NAME")" ]; then
    docker network connect kind "$REG_NAME"
  fi
}

cluster_up() {
  mkdir -p "$STATE/audit"
  cat >"$STATE/audit/policy.yaml" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["pods", "pods/binding"]
      - group: "agents.x-k8s.io"
      - group: "extensions.agents.x-k8s.io"
      - group: "fiberd.io"
  - level: None
EOF
  cat >"$STATE/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $STATE/audit
        containerPath: /var/log/kube-audit
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-policy-file: /etc/kubernetes/audit-policy.yaml
            audit-log-path: /var/log/kube-audit/audit.log
          extraVolumes:
            - name: audit-policy
              hostPath: /var/log/kube-audit/policy.yaml
              mountPath: /etc/kubernetes/audit-policy.yaml
              readOnly: true
              pathType: File
            - name: audit-log
              hostPath: /var/log/kube-audit
              mountPath: /var/log/kube-audit
              pathType: DirectoryOrCreate
        scheduler:
          extraArgs:
            bind-address: "0.0.0.0"
            authorization-always-allow-paths: /healthz,/readyz,/livez,/metrics
EOF
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$STATE/kind.yaml" --wait 120s
  # journald's per-service rate limit can drop the goroutine dump of a
  # containerd crash under a burst, so the node keeps every line.
  docker exec "$NODE" sh -c 'test -f /etc/systemd/journald.conf.d/compare.conf || {
    mkdir -p /etc/systemd/journald.conf.d
    printf "[Journal]\nRateLimitIntervalSec=0\nRateLimitBurst=0\n" > /etc/systemd/journald.conf.d/compare.conf
    systemctl restart systemd-journald; }'
  # systemd gives every container 15% of threads-max in tasks by default,
  # and 50 restored gVisor sandboxes need more. The limit stays explicit,
  # so a fiberd home can see it and keep its reserve below it.
  docker exec "$NODE" sh -c 'test -f /etc/systemd/system.conf.d/compare.conf || {
    mkdir -p /etc/systemd/system.conf.d
    printf "[Manager]\nDefaultTasksMax=16384\n" > /etc/systemd/system.conf.d/compare.conf
    systemctl daemon-reexec; }'
  # The registry, as kind's local-registry recipe wires it.
  docker exec "$NODE" sh -c "mkdir -p /etc/containerd/certs.d/localhost:$REG_PORT && printf '[host.\"http://$REG_NAME:5000\"]\n' > /etc/containerd/certs.d/localhost:$REG_PORT/hosts.toml"
  "${KC[@]}" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata: { name: local-registry-hosting, namespace: kube-public }
data:
  localRegistryHosting.v1: |
    host: "localhost:$REG_PORT"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

gvisor_up() {
  local arch work sum
  arch=$(docker info -f '{{.Architecture}}')
  work=$(mktemp -d)
  for b in runsc containerd-shim-runsc-v1; do
    docker exec "$NODE" sh -c "test -x /usr/local/bin/$b" 2>/dev/null && continue
    case "$b-$arch" in
      runsc-x86_64) sum=$RUNSC_SHA512_X86_64 ;;
      runsc-aarch64) sum=$RUNSC_SHA512_AARCH64 ;;
      containerd-shim-runsc-v1-x86_64) sum=$SHIM_SHA512_X86_64 ;;
      containerd-shim-runsc-v1-aarch64) sum=$SHIM_SHA512_AARCH64 ;;
      *) echo "no pinned $b for $arch" >&2; exit 1 ;;
    esac
    curl -fsSL -o "$work/$b" "https://storage.googleapis.com/gvisor/releases/release/$RUNSC_RELEASE/$arch/$b"
    echo "$sum  $work/$b" | shasum -a 512 -c - >/dev/null
    docker cp "$work/$b" "$NODE:/usr/local/bin/$b"
    docker exec "$NODE" chmod 0755 "/usr/local/bin/$b"
  done
  rm -rf "$work"
  docker exec "$NODE" sh -c 'grep -q runsc /etc/containerd/config.toml || cat >>/etc/containerd/config.toml <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
  printf "[runsc_config]\n  platform = \"systrap\"\n" > /etc/containerd/runsc.toml
  systemctl restart containerd'
  "${KC[@]}" apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: { name: gvisor }
handler: runsc
EOF
}

# registry_addr is the registry as the grant Pods reach it: the
# container's address on the kind network, port 5000.
registry_addr() {
  local ip
  ip=$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}{{.IPAddress}}{{end}}' "$REG_NAME")
  [ -n "$ip" ] || { echo "registry $REG_NAME is not on the kind network" >&2; exit 1; }
  echo "$ip:5000"
}

case "${1:-}" in
  up) registry_up; cluster_up; registry_join; gvisor_up; echo "cluster kind-$CLUSTER up, registry localhost:$REG_PORT, audit $STATE/audit/audit.log" ;;
  registry-addr) registry_addr ;;
  down) kind delete cluster --name "$CLUSTER"; docker rm -f "$REG_NAME" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 up|registry-addr|down" >&2; exit 2 ;;
esac
