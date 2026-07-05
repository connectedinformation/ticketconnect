#!/usr/bin/env bash
# Host acceptance demo (DESIGN §13, pre-k8s): an already-running, unmodified
# looping TLS client starts making full handshakes; then the injector is
# "deployed" and — without touching the client — its next connections resume on
# a PQC-derived PSK. Needs BPF privilege (sudo) for the injector.
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"
root="$here/.."
port="${PORT:-15450}"
sock="$(mktemp -u /tmp/tc-agent.XXXXXX.sock)"
work="$(mktemp -d)"

srv_pid=""; agent_pid=""; inj_pid=""; cli_pid=""
cleanup() {
    for p in "$cli_pid" "$inj_pid" "$agent_pid" "$srv_pid"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    sudo pkill -f "injector --agent $sock" 2>/dev/null || true
    rm -rf "$work" "$sock"
}
trap cleanup EXIT

echo "== build =="
make -C "$root/ticket-agent" >/dev/null
make -C "$root/injector" >/dev/null
make -C "$here" >/dev/null

echo "== PQC server on :$port =="
openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
openssl s_server -accept "$port" -cert "$work/cert.pem" -key "$work/key.pem" \
    -tls1_3 -groups X25519MLKEM768 -quiet &
srv_pid=$!
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; break; fi
    sleep 0.1
done

echo "== agent: pre-warm a pool and serve over $sock =="
"$root/ticket-agent/ticket-agent" serve "$sock" "127.0.0.1:$port" -k --depth 16 &
agent_pid=$!
for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done

echo "== start the unmodified looping client (10 connections) =="
"$here/loop_client" 127.0.0.1 "$port" 10 700 &
cli_pid=$!

# Let it make a couple of full handshakes first, then "deploy" the injector.
sleep 1.8
echo "== deploy the injector against pid $cli_pid =="
sudo "$root/injector/injector" --agent "$sock" --dest "127.0.0.1:$port" --pid "$cli_pid" &
inj_pid=$!

wait "$cli_pid"
echo "== done (full before deploy, RESUMED after) =="
