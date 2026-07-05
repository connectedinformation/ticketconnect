#!/usr/bin/env bash
# Prove the demo's resumption is genuinely the INJECTED ticket, not the client
# self-resuming after a full handshake. Two independent proofs:
#
#   1. Negative control: the same cache-off client with NO injector never resumes,
#      so it CANNOT self-resume — every RESUMED must come from an injected session.
#   2. Wire tie: capture the handshakes and show the ticket the client presents in
#      its ClientHello pre_shared_key == the ticket the AGENT fetched (byte-for-
#      byte), and that the ServerHello accepts that PSK (selected_identity).
#
# Needs: openssl (3.5), tshark, tcpdump (sudo), and the built binaries.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
sd="$(mktemp -d)"; port="${PORT:-15490}"; cap="$sd/cap.pcap"; srv=""
cleanup(){ sudo pkill -f "tcpdump -i lo -w $cap" 2>/dev/null; [ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$sd"; }
trap cleanup EXIT

make -C demo >/dev/null 2>&1
make -C injector test/test_install >/dev/null 2>&1
cc -O2 $(pkg-config --cflags openssl) -x c -o "$sd/ticket_hex" - $(pkg-config --libs openssl) <<'EOF'
#include <openssl/ssl.h>
#include <stdio.h>
int main(int c, char** v){ FILE* f=fopen(v[1],"rb"); unsigned char b[16384];
  size_t n=fread(b,1,sizeof b,f); fclose(f); const unsigned char* p=b;
  SSL_SESSION* s=d2i_SSL_SESSION(0,&p,(long)n); if(!s) return 2;
  const unsigned char* t; size_t l; SSL_SESSION_get0_ticket(s,&t,&l);
  for(size_t i=0;i<l;i++) printf("%02x",t[i]); printf("\n"); return 0; }
EOF

openssl req -x509 -newkey rsa:2048 -keyout "$sd/key.pem" -out "$sd/cert.pem" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
openssl s_server -accept "$port" -cert "$sd/cert.pem" -key "$sd/key.pem" -tls1_3 -groups X25519MLKEM768 -quiet >/dev/null 2>&1 &
srv=$!
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; break; }; sleep 0.1; done

echo "== 1. NEGATIVE CONTROL: cache-off client, NO injector =="
./demo/loop_client 127.0.0.1 "$port" 5 150 2>&1 | grep -E '\[' | sed 's/^/   /'
echo "   -> must be all 'full' (the client cannot resume on its own)"

echo
echo "== 2. WIRE TIE: agent fetch -> inject -> resume, captured =="
sudo tcpdump -i lo -w "$cap" "tcp port $port" >/dev/null 2>&1 &
sleep 1.5
timeout 25 ./ticket-agent/ticket-agent fetch 127.0.0.1 "$port" -k -o "$sd/sess.der" >/dev/null
timeout 25 ./injector/test/test_install 127.0.0.1 "$port" "$sd/sess.der" >/dev/null 2>&1
sleep 1; sudo pkill -f "tcpdump -i lo -w $cap" 2>/dev/null; sleep 0.5
sudo chmod a+r "$cap" 2>/dev/null

DA="-d tcp.port==$port,tls"
agent_ticket=$("$sd/ticket_hex" "$sd/sess.der")
wire_ticket=$(tshark -r "$cap" $DA -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions.psk.identity.identity 2>/dev/null | tr -d ':' | grep . | head -1)
selected=$(tshark -r "$cap" $DA -Y 'tls.handshake.type==2' \
  -T fields -e tls.handshake.extensions.psk.identity.selected 2>/dev/null | grep . | head -1)

echo "   agent-fetched ticket (session) : ${#agent_ticket} hex chars ($(( ${#agent_ticket}/2 )) bytes)"
echo "   ticket on the wire (ClientHello): ${#wire_ticket} hex chars ($(( ${#wire_ticket}/2 )) bytes)"
echo "   ServerHello selected_identity   : ${selected:-<none>}  (server accepted the PSK)"
if [ -n "$wire_ticket" ] && [ "$agent_ticket" = "$wire_ticket" ]; then
    echo "   RESULT: MATCH — the client presented the exact ticket the agent fetched."
else
    echo "   RESULT: mismatch / not captured"
    echo "     agent=${agent_ticket:0:32}..."
    echo "     wire =${wire_ticket:0:32}..."
fi
