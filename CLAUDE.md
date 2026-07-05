# CLAUDE.md

Guidance for Claude Code in the ticketconnect repository.

## Project Overview

ticketconnect gives a legacy TLS *endpoint* (client or server) post-quantum key
material — or a certificate-free resumed path — it cannot negotiate itself,
without changing its code, image, or deployment. An agent performs the handshake
the endpoint cannot (or need not) perform and installs the resulting TLS 1.3
resumption session into it, so the endpoint's own next connection resumes on a
PQC-rooted PSK — off the data path. The substance is the off-path
session-acquisition-and-injection **primitive**; stock OpenSSL 3.5 supplies the
PQC for free, so PQC is the marquee use case, not the product.

**The design is the source of truth.** Build from `docs/DESIGN.md`, which is the
specification; the implementation derives from it.

Full spec: [docs/DESIGN.md](docs/DESIGN.md).

## Architecture

**One authority, two delivery planes** — full detail in `docs/DESIGN.md` §5 and
`docs/adr/0001-two-plane-architecture.md`. The mechanism is chosen per connection
by **injectability** (can we `ptrace` the endpoint): `inject-both` / `inject-one`
/ `inject-none`. East/north-south = traffic direction only, never a proxy for
injectability.

- **Authority — `ticket-agent`** (unprivileged): X25519MLKEM768 handshakes via
  stock OpenSSL 3.5; sources sessions by **relay** or **mint**; holds the
  per-destination session **pool** (freshness, single-use headroom); serves
  sessions + PQC provenance over a node-local Unix socket. All network-facing PQC
  code lives here.
- **Plane 1 — injection (off-path). `injector`** (privileged: `CAP_BPF`,
  `CAP_PERFMON`, `CAP_SYS_PTRACE`, `hostPID`): eBPF CO-RE uprobes for
  detection/timing; ptrace installs the session (client) or STEK (server) via
  **public OpenSSL APIs only** (remote `d2i_SSL_SESSION` + `SSL_set_session`) —
  never private struct offsets. This rule makes the memory-corruption bug class
  *unrepresentable*. Packaged as the DaemonSet.
- **Plane 2 — fronting (on-path). `gateway` + `frontdesk`** (deferred, gated):
  for `inject-none` peers only — `gateway` steers by ClientHello, `frontdesk`
  terminates a handshake to issue a ticket. Bounded to ticket issuance; packaged
  as a Deployment/Service. A ClientHello steerer is one role, not four
  components — its dataplane (userspace proxy, sockmap, XDP) is an impl choice.

Modes: **v1 = relay** (upstream mints the ticket; Plane 1, inject-one client;
delivers resumption + attested PQC provenance). **Authority mode** (agent owns
the STEK, mints tickets, embeds metadata, cert-free path) unlocks server-side
injection and the fronting plane — deferred. Build order in DESIGN.md §12.

Boundary: self-contained on stock OpenSSL 3.5; do not couple to any external
on-path/inline engine. The on-path fronting plane is the closest brush with that
boundary — keep it bounded and gated (re-check DESIGN.md §11 before investing).

## Build

Skeleton — see the top-level `Makefile` (`make help`). Components live in
`ticket-agent/`, `injector/`, `bpf/`.

## Coding Conventions

- **Style: Bjarne Stroustrup's C/C++ layout**, enforced by `.clang-format` (run
  it before commit). Key points:
  - Function / class / namespace opening brace on its own line; control-statement
    braces attached (`if (x) {`).
  - 4-space indent, no tabs. Column limit 100.
  - Pointer bound to the type: `int* p`, not `int *p`. One declaration per line
    (never `int* p, q;`).
- **Language: C is primary** — it fits the eBPF/systems substrate and keeps the
  injection surface to the plain C ABI. Use C++ only where it clearly earns it.
- Naming: types `Capitalized_with_underscores`; functions/variables `snake_case`;
  namespaces `name_space`.
- Headers: system headers first, then local, each alphabetical.
- Comments minimal; code self-explanatory. Cite RFC sections (RFC 8446 TLS 1.3,
  RFC 5077 tickets) where wire format matters.

## Security Invariants (DESIGN.md §10)

- Enforce `psk_dhe_ke`. Never `psk_ke`, never 0-RTT.
- No silent downgrade: a miss/failure falls back to normal TLS **and emits an
  event**.
- ptrace acts only on verified targets, fail-closed; `PTRACE_O_EXITKILL` always.
- Server-side injection is *not* risk-symmetric with client-side (long-lived
  shared STEK, live-traffic process) — treat with authority-mode STEK cautions.

## Non-goals

General on-path traffic proxy / service mesh (the fronting plane is a *bounded*
ticket issuer, not a traffic splicer); non-OpenSSL stacks; **cluster-wide** ticket
pooling (the per-destination freshness pool IS in scope); SaaS control plane;
0-RTT.
