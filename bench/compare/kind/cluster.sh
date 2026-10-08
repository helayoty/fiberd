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
STATE=${COMPARE_STATE:-$PWD/bin/compare-state}
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
            authorization-always-allow-paths: /healthz,/readyz,/livez,/metrics
EOF
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --config "$STATE/kind.yaml" --wait 120s
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
  local arch work
  arch=$(docker info -f '{{.Architecture}}')
  work=$(mktemp -d)
  for b in runsc containerd-shim-runsc-v1; do
    docker exec "$NODE" sh -c "test -x /usr/local/bin/$b" 2>/dev/null && continue
    curl -fsSL -o "$work/$b" "https://storage.googleapis.com/gvisor/releases/release/$RUNSC_RELEASE/$arch/$b"
    curl -fsSL -o "$work/$b.sha512" "https://storage.googleapis.com/gvisor/releases/release/$RUNSC_RELEASE/$arch/$b.sha512"
    (cd "$work" && sed "s| .*|  $b|" "$b.sha512" | shasum -a 512 -c -)
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
