#!/usr/bin/env bash
# PQC s_server for the demo: self-signed cert, TLS 1.3, X25519MLKEM768 only.
set -euo pipefail
port="${PORT:-4433}"
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
    -days 1 -nodes -subj "/CN=demo-server" 2>/dev/null
exec openssl s_server -accept "$port" -cert /tmp/cert.pem -key /tmp/key.pem \
    -tls1_3 -groups X25519MLKEM768 -quiet
