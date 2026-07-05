#!/usr/bin/env bash
# Network tests (Tiers 1–2 + the serve/get authority path). Stands up a PQC
# s_server, runs the direct session tests, then proves the pool+UDS path serves a
# real resumable session end to end. Unprivileged; CI-safe.
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"
agent="$here/../ticket-agent"
port="${PORT:-14433}"
work="$(mktemp -d)"
sock="$work/agent.sock"

srv_pid=""
agent_pid=""
cleanup() {
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null || true
    [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

openssl s_server -accept "$port" -cert "$work/cert.pem" -key "$work/key.pem" \
    -tls1_3 -groups X25519MLKEM768 -quiet &
srv_pid=$!

for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; break; fi
    sleep 0.1
done

# Direct session source (Tiers 1–2).
"$here/test_session" 127.0.0.1 "$port"

# Authority path: serve a pre-warmed pool over UDS, then a client GET.
echo "== authority path (serve + get over UDS) =="
"$agent" serve "$sock" "127.0.0.1:$port" -k --depth 2 &
agent_pid=$!
for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done

"$agent" get "$sock" "127.0.0.1:$port" -o "$work/uds.der"

fails=0
if [ -s "$work/uds.der" ]; then echo "  ok   : UDS delivered a non-empty session"; else
    echo "  FAIL : UDS delivered an empty session"; fails=1; fi
if openssl sess_id -inform DER -in "$work/uds.der" -noout -text 2>/dev/null | grep -q "Resumption PSK"; then
    echo "  ok   : UDS-delivered session carries a Resumption PSK"; else
    echo "  FAIL : UDS-delivered session is not a resumable SSL_SESSION"; fails=1; fi

echo ""
[ "$fails" -eq 0 ] && echo "authority path: PASS" || { echo "authority path: FAIL"; exit 1; }
