# Security Policy

## Status

ticketconnect is **experimental** — a working, end-to-end-proven v1, **not**
production-hardened (see the maturity note in the [README](README.md)). Do not
deploy it against production traffic without your own review. There are no
supported/LTS releases yet; security fixes land on `main`.

## What ticketconnect is (for threat modeling)

A per-node Kubernetes DaemonSet with two components:

- **`ticket-agent`** (unprivileged) — performs TLS 1.3 handshakes and serves the
  resulting resumption sessions over a **node-local Unix socket**.
- **`injector`** (privileged: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`,
  `hostPID`) — detects `SSL_connect` via an eBPF uprobe and installs a session
  into the target process via `ptrace`.

The injector is a **node-wide, root-equivalent** component that can read and
write the memory of other processes on the node. Treat it as part of your node
TCB, with the same trust you would give any privileged DaemonSet (Cilium, Falco,
Tetragon).

## Security properties (design intent)

- **Public-API-only injection.** The injector calls only *exported* OpenSSL
  functions (`d2i_SSL_SESSION`, `SSL_set_session`, …) by resolved symbol address;
  it never writes private struct fields. This makes the memory-corruption bug
  class of offset-based injection *unrepresentable*. A failed install leaves the
  target running and uncorrupted — **worst case is "no upgrade," never a
  corrupted process.**
- **Fail-closed.** Unresolved symbols, an unverified target, or a malformed
  payload abort before any write. `PTRACE_O_EXITKILL` ensures a dead injector
  never leaves a target stopped.
- **No silent downgrade.** A miss (no session available) falls back to normal TLS
  *and emits an event*, rather than quietly degrading.
- **`psk_dhe_ke` enforced.** Never `psk_ke`, never 0-RTT.

## Risks and blast radius (stated plainly)

- **Privilege.** The injector is root-equivalent and node-wide. A bug or
  compromise in it can affect any process on the node.
- **Availability.** The eBPF uprobe briefly freezes (`SIGSTOP`) a client at
  `SSL_connect` entry while the injector installs a session; a malfunction could
  stall TLS clients. The agent is excluded (by comm) to avoid self-deadlock.
- **STEK trust concentration (authority mode — not in v1).** If/when the agent
  mints tickets, the shared STEK is a high-value secret: its compromise decrypts
  *and forges* any client's tickets. Scope to internal, controlled traffic only.
- **Demo insecurity.** The demos use `SSL_VERIFY_NONE` and self-signed certs —
  **demo only.** The relay path authenticates to the real upstream normally.

## Reporting a vulnerability

**Please report privately — do not open a public issue.**

- **Preferred:** GitHub private vulnerability reporting — *Security → Report a
  vulnerability* on this repository.
- **Email:** `security@connectedinformation.io`

Please include a description, affected component/version (commit), reproduction
steps, and impact. We aim to acknowledge within **5 business days** and to
coordinate disclosure; we will credit reporters who wish to be credited.

## Scope

- **In scope:** the `ticket-agent`, `injector`, `bpf`, and `deploy` code in this
  repository.
- **Out of scope:** OpenSSL, libbpf, the Linux kernel, Kubernetes, and
  third-party base images — report those to their respective projects.
