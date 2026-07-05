#!/usr/bin/env bash
# Tier 4 acceptance demo on kind (DESIGN §13): deploy the DaemonSet next to an
# already-running, unmodified client, and watch its connections transition from
# full handshakes to PQC resumption — with no change to the client.
#
#   ./deploy/run_kind_demo.sh          # build, load, deploy, observe
#   ./deploy/run_kind_demo.sh clean    # tear the cluster down
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"
root="$here/.."
cluster="ticketconnect"

if [ "${1:-}" = "clean" ]; then
    kind delete cluster --name "$cluster"
    exit 0
fi

echo "== generate vmlinux.h + build images =="
make -C "$root/bpf" vmlinux.h >/dev/null
docker build -q -f "$root/deploy/Dockerfile.agent"    -t ticketconnect/agent:dev    "$root" >/dev/null
docker build -q -f "$root/deploy/Dockerfile.injector" -t ticketconnect/injector:dev "$root" >/dev/null
docker build -q -f "$root/deploy/Dockerfile.demo"     -t ticketconnect/demo:dev     "$root" >/dev/null

echo "== create kind cluster =="
kind get clusters 2>/dev/null | grep -qx "$cluster" || kind create cluster --config "$here/kind-config.yaml"

echo "== load images into the node =="
kind load docker-image --name "$cluster" ticketconnect/agent:dev ticketconnect/injector:dev ticketconnect/demo:dev

echo "== deploy (rewrite the published image refs to the locally-built :dev) =="
tmp="$(mktemp -d)"
sub='s#ghcr.io/connectedinformation/ticketconnect-\(agent\|injector\|demo\):v0.1.0#ticketconnect/\1:dev#'
sed "$sub" "$here/k8s/daemonset.yaml" > "$tmp/daemonset.yaml"
sed "$sub" "$here/k8s/demo.yaml" > "$tmp/demo.yaml"
kubectl apply -f "$tmp/daemonset.yaml"
kubectl apply -f "$tmp/demo.yaml"
rm -rf "$tmp"

echo "== wait for rollout =="
kubectl -n ticketconnect rollout status ds/ticketconnect --timeout=120s
kubectl -n ticketconnect rollout status deploy/demo-server --timeout=120s
kubectl -n ticketconnect rollout status deploy/demo-client --timeout=120s

echo "== client log (expect: full handshakes, then RESUMED) =="
kubectl -n ticketconnect logs -l app=demo-client --tail=30 -f &
logpid=$!
sleep 20
kill "$logpid" 2>/dev/null || true

echo "== done. 'run_kind_demo.sh clean' to tear down. =="
