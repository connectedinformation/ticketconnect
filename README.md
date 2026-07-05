# ticketconnect

[![CI](https://github.com/connectedinformation/ticketconnect/actions/workflows/ci.yml/badge.svg)](https://github.com/connectedinformation/ticketconnect/actions/workflows/ci.yml) [![license](https://img.shields.io/badge/license-MIT%20%2B%20GPL-blue.svg)](LICENSE) [![status](https://img.shields.io/badge/status-experimental-orange.svg)](#status--maturity)

> **Post-quantum protection for legacy TLS clients you can't change — installed
> off the data path by an eBPF + ptrace node agent, with zero application change.**

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

## Status & maturity

**Experimental.** ticketconnect is a working, end-to-end-*proven* v1 — but it is
proof-of-concept-grade, not production-hardened.

*Proven:* the host acceptance demo (`demo/run_host_demo.sh`) and a real-cluster
run on GKE — an unmodified client resumed on X25519MLKEM768 for 111 consecutive
connections, and the resumed ticket is verified byte-for-byte against the agent's
(`demo/verify_injection.sh`).

*Not yet:* sustained load/soak testing; broad coverage (currently **x86-64 +
OpenSSL only**); multi-destination injection (v1 is single-destination);
concurrency hardening for multi-threaded targets; production observability (events
are stderr today). **Do not put production traffic on it without your own review.**
The injector is a privileged, node-wide component — read [SECURITY.md](SECURITY.md)
before deploying.

Source of truth:
[docs/DESIGN.md](docs/DESIGN.md) (spec) ·
[docs/adr/0001-two-plane-architecture.md](docs/adr/0001-two-plane-architecture.md)
(architecture) · [docs/TEST_PLAN.md](docs/TEST_PLAN.md) (testing).

## Try it

On a single host, no cloud (needs OpenSSL 3.5 and `sudo` for the eBPF injector):

```
./demo/run_host_demo.sh
```

An unmodified looping client does full handshakes, then — the moment the injector
is deployed, with no change to the client — its connections become PQC
resumptions. See [deploy/](deploy/) for containers, the DaemonSet, and kind/GKE.

## License

MIT — see [LICENSE](LICENSE) — **except** the eBPF program
`bpf/ssl_connect.bpf.c`, which is **GPL-2.0** (`SEC("license") = "GPL"`),
required because it uses GPL-only kernel helpers (`bpf_send_signal`,
`bpf_get_ns_current_pid_tgid`). That GPL scope is limited to the BPF object loaded
into the kernel; the rest — agent, injector userspace, tooling — is MIT.

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities:
[SECURITY.md](SECURITY.md).
