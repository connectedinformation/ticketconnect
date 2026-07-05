#!/usr/bin/env bash
# Real-world acceptance demo on GKE (DESIGN §13). Unlike kind, a GKE Standard node
# is the root PID namespace, so hostPID + eBPF + ptrace line up and the full
# detect -> freeze -> install -> resume flow runs end to end.
#
#   ./run_gke_demo.sh          # provision, build+push, deploy, observe
#   ./run_gke_demo.sh clean    # delete the cluster (stop billing)
#
# Standard cluster (Autopilot forbids privileged/hostPID/BPF), Ubuntu nodes (BTF
# for CO-RE). Dedicated project keeps the tlslane boundary crisp.
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"
root="$here/../.."
PROJECT="${PROJECT:-ci-ticketconnect}"
ZONE="${ZONE:-asia-east1-a}"
CLUSTER="${CLUSTER:-tc-demo}"
TAG="${TAG:-demo}"
AR="asia-east1-docker.pkg.dev/$PROJECT/ticketconnect"

if [ "${1:-}" = "clean" ]; then
    gcloud container clusters delete "$CLUSTER" --project "$PROJECT" --zone "$ZONE" --quiet
    exit 0
fi

echo "== project + APIs + registry =="
gcloud config set project "$PROJECT"
gcloud services enable container.googleapis.com artifactregistry.googleapis.com --project "$PROJECT"
gcloud artifacts repositories create ticketconnect --repository-format=docker \
    --location=asia-east1 --project "$PROJECT" 2>/dev/null || true
gcloud auth configure-docker asia-east1-docker.pkg.dev --quiet

echo "== build + push images =="
make -C "$root/bpf" vmlinux.h >/dev/null
for c in agent injector demo; do
    docker build -q -f "$root/deploy/Dockerfile.$c" -t "$AR/$c:$TAG" "$root" >/dev/null
    docker push "$AR/$c:$TAG" >/dev/null
done

echo "== cluster =="
gcloud container clusters describe "$CLUSTER" --project "$PROJECT" --zone "$ZONE" >/dev/null 2>&1 ||
    gcloud container clusters create "$CLUSTER" --project "$PROJECT" --zone "$ZONE" \
        --num-nodes 1 --machine-type e2-medium --image-type UBUNTU_CONTAINERD \
        --scopes cloud-platform --no-enable-autoupgrade --no-enable-autorepair
gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT" --zone "$ZONE"

echo "== deploy (AR images) =="
tmp="$(mktemp -d)"
sed "s#ticketconnect/\(agent\|injector\|demo\):dev#$AR/\1:$TAG#; s#IfNotPresent#Always#" \
    "$here/../k8s/daemonset.yaml" > "$tmp/daemonset.yaml"
sed "s#ticketconnect/\(agent\|injector\|demo\):dev#$AR/\1:$TAG#; s#IfNotPresent#Always#" \
    "$here/../k8s/demo.yaml" > "$tmp/demo.yaml"
kubectl apply -f "$tmp/daemonset.yaml"
kubectl apply -f "$tmp/demo.yaml"
rm -rf "$tmp"

echo "== wait + observe =="
kubectl -n ticketconnect rollout status ds/ticketconnect --timeout=180s
kubectl -n ticketconnect rollout status deploy/demo-server --timeout=180s
kubectl -n ticketconnect rollout status deploy/demo-client --timeout=180s
sleep 25
kubectl -n ticketconnect logs -l app=demo-client --tail=20

echo "== done. './run_gke_demo.sh clean' to delete the cluster. =="
