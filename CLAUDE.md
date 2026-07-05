# CLAUDE.md

Guidance for Claude Code in the ticketconnect repository.

## Project Overview

ticketconnect gives a legacy TLS client post-quantum key material it cannot
negotiate itself, without changing its code, image, or deployment. A PQC-capable
node agent performs the X25519MLKEM768 handshake on the client's behalf and
installs the resulting TLS 1.3 resumption session into the client, so the
client's own next connection resumes on a quantum-safe PSK — off the data path.

**Clean-room reimplementation.** Do NOT import code, docs, or git history from
any prior tree (`~/Projects/ticketconnect-legacy`, `~/Projects/TicketConnect.0`).
Rebuild from `docs/DESIGN.md`, which is the specification. Learn from the prior
prototype; do not reuse its code.

Full spec: [docs/DESIGN.md](docs/DESIGN.md).

## Architecture

DaemonSet node agent, two containers (least privilege):

- **ticket-agent** (unprivileged): X25519MLKEM768 handshakes via stock OpenSSL
  3.5; per-destination resumption-session pool; serves sessions + PQC provenance
  over a node-local Unix socket.
- **injector** (privileged: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`,
  `hostPID`): eBPF CO-RE uprobes for detection/timing; ptrace performs the
  install via **public OpenSSL APIs only** (remote `d2i_SSL_SESSION` +
  `SSL_set_session`) — never private struct offsets. This rule makes the
  memory-corruption bug class *unrepresentable*.

Modes: **v1 = relay** (the upstream mints the ticket; delivers resumption +
attested PQC provenance). **Authority mode** (agent owns the STEK, mints tickets,
embeds metadata, cert-free path) is deferred.

Boundary: must **not** depend on the tlslane project's closed code. Self-contained
on stock OpenSSL 3.5.

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

## Security Invariants (DESIGN.md §8)

- Enforce `psk_dhe_ke`. Never `psk_ke`, never 0-RTT.
- No silent downgrade: a miss/failure falls back to normal TLS **and emits an
  event**.
- ptrace acts only on verified targets, fail-closed; `PTRACE_O_EXITKILL` always.

## Non-goals

On-path proxy / service mesh; non-OpenSSL stacks; ticket pooling; SaaS control
plane; 0-RTT.
