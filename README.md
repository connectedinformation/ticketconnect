# ticketconnect

Give a legacy TLS endpoint post-quantum key material — or a certificate-free
resumed path — it cannot negotiate itself, without changing its code, its image,
or its deployment.

An agent performs the handshake a legacy endpoint cannot (or need not) perform
for itself and installs the resulting TLS 1.3 resumption session into it, so the
endpoint's *own* next connection resumes on a PQC-rooted PSK — **off the data
path, with zero application change.**

The substance is the off-path **session-acquisition-and-injection primitive**,
not the cryptography: stock OpenSSL 3.5 supplies X25519MLKEM768 for free, and
once a session exists the connection is ordinary TLS 1.3 PSK resumption. PQC is
the marquee use case, not the product.

## How it works

The primitive is **symmetric** — the same machinery installs a session into a
*client* (so it resumes outbound) or a STEK into a *server* (so it accepts a
minted ticket). One authority feeds two delivery planes, selected per connection
by whether we can reach (`ptrace`) the endpoint:

- **Injection (off-path)** — for reachable endpoints. An eBPF uprobe detects the
  connection; a privileged injector installs the session via **public OpenSSL
  APIs only** (`d2i_SSL_SESSION` + `SSL_set_session`), never private struct
  offsets. Endpoints connect directly; nothing sits on the data path. *This is
  the v1 target.*
- **Fronting (on-path)** — for endpoints we cannot reach (an external browser, a
  partner server): a gateway steers by ClientHello and a frontdesk terminates the
  handshake to issue a ticket. Bounded to ticket issuance, deferred behind the
  off-path core.

Deployed as a DaemonSet, two least-privilege containers: an unprivileged
`ticket-agent` (does the handshakes, holds the session pool) and a privileged
`injector` (eBPF detection + ptrace install).

Two invariants are non-negotiable: **no silent downgrade** (a miss falls back to
normal TLS *and emits an event*) and **`psk_dhe_ke` always** (never `psk_ke`,
never 0-RTT).

## Status

Pre-release, in active development. The design is the source of truth:

- [docs/DESIGN.md](docs/DESIGN.md) — full specification.
- [docs/adr/0001-two-plane-architecture.md](docs/adr/0001-two-plane-architecture.md)
  — the one-authority / two-plane architecture decision.

## License

MIT — see [LICENSE](LICENSE).
