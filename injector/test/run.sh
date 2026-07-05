#!/usr/bin/env bash
# Tier 3 integration: agent fetches a real session, injector installs it into a
# live libssl client, client resumes. Needs a PQC s_server and the ticket-agent
# binary (built on demand). Traces its own child -> unprivileged.
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"
agent_dir="$here/../../ticket-agent"
port="${PORT:-15443}"
work="$(mktemp -d)"

srv_pid=""
cleanup() {
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

# Agent fetches a genuine resumption session for this server.
make -C "$agent_dir" >/dev/null
"$agent_dir/ticket-agent" fetch 127.0.0.1 "$port" -k -o "$work/sess.der" >/dev/null

# Injector installs it into a live victim; victim must resume.
"$here/test_install" 127.0.0.1 "$port" "$work/sess.der"
