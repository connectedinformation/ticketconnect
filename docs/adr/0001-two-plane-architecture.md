# ADR-0001 — One authority, two delivery planes

Status: Accepted (2026-07-05)

## Context

The initial clean-room design kept a single component, `ticket-agent`: it sources a session by an
outbound handshake and the injector installs that session into a local **client**, which then
resumes. This is **client-side only**, and it structurally fails the two cases the project actually
targets:

- **Server does not support PQC** → there is no PQC ticket upstream to relay.
- **Server has no / needs no certificate + private key** → there is no server handshake to relay
  from at all.

Both require *minting* a ticket locally (authority mode) rather than relaying one, and require the
serving endpoint to hold the minting **STEK**. The reframed goal is therefore **symmetric
always-resume**: make *both* endpoints do TLS 1.3 PSK resumption, driven by either "can't do PQC" or
"no/needless certificate." Resumption is the universal substrate because it removes both the wire
key-exchange and the certificate from the resumed path.

The prior prototype answered the server side with a tier of components — `ticket_frontdesk`,
`frontdesk_router`, `clienthello_router`, `xdp_router`, `ticket_gateway` — that terminate or steer
**live** TLS connections. That tier is on the data path, which (a) re-invents TLS Lane's closed
inline engine and (b) was an explicit non-goal. But the review also observed the tier existed only
because the frontdesk served **external, un-injectable** clients (browsers); when both endpoints are
processes we control, injection reaches the server too, off-path.

The deciding variable is **injectability** (can we `ptrace` the endpoint?), not traffic direction
(east-west / north-south), which were being conflated.

## Decision

Adopt a **one-authority / two-plane** architecture, selected per connection by injectability
(`inject-both` / `inject-one` / `inject-none`; see DESIGN.md §3):

1. **Authority — `agent` (+ pool).** Single source of truth for session material. Sources by
   **relay** (outbound handshake) or **mint** (local PSK sealed under a shared STEK). The
   per-destination **pool** is its inventory, sits between sourcing and delivery, is plane-agnostic,
   and makes off-path injection latency-free and single-use-safe.

2. **Plane 1 — injection (off-path). `agent` + `injector`.** For reachable endpoints. The injector
   `ptrace`-installs a session into a client or a STEK into a server, via **public OpenSSL APIs
   only**. Endpoints connect directly; nothing on the data path. Covers `inject-both` and
   `inject-one`. This is the headline capability and the v1 build target.

3. **Plane 2 — fronting (on-path). `gateway` + `frontdesk`.** For un-injectable endpoints
   (`inject-none`). `gateway` steers by ClientHello (PSK → backend; PQC-no-PSK → frontdesk; neither
   → backend + event); `frontdesk` terminates the peer's handshake and issues a STEK-sealed ticket.
   On the data path, consciously scoped, **build deferred and gated** behind Plane 1.

Unifying invariant: **one shared STEK feeds both planes**, so a ticket minted by the frontdesk is
decryptable by an agent-injected server and vice versa.

Two sub-decisions:

- **Collapse `router`/`gateway`/`clienthello_router`/`xdp_router` into one `gateway`.** They were
  four dataplane implementations (userspace `splice` → sockmap → XDP) of one role: steer by
  ClientHello. Dataplane layer is an implementation choice (start userspace), not four components.
  The prior fourfold split (and its 4 divergent ClientHello parsers / 3 PQC-codepoint tables) was a
  flagged defect; do not reproduce it.
- **Packaging follows the planes:** off-path plane = DaemonSet (`agent` unprivileged + `injector`
  privileged); on-path plane = Deployment/Service (network endpoints, no `ptrace` privilege).

## Consequences

**Positive**
- Covers the full symmetric goal (both endpoints, both drivers) with one coherent model.
- Keeps the differentiator intact: the default, headline path is **off-path**; the on-path tier is
  the explicit exception for un-injectable peers, not the norm.
- Clean privilege story: the component holding key material (`agent`) is unprivileged; the
  privileged `injector` holds no long-term secret.
- Authority mode's local minting makes deep pools cheap to keep warm — a benefit independent of the
  cert-free story.

**Negative / risks**
- **Server injection is not risk-symmetric with client injection**: a STEK is long-lived, shared,
  and installed into a process serving live traffic; it will accept any ticket sealed under it. Treat
  with authority-mode STEK cautions, not relay defaults.
- **Plane 2 is the closest brush with TLS Lane's closed on-path engine.** It is bounded (issues
  tickets, does not splice arbitrary traffic), but the boundary is thin; re-check DESIGN.md §11 and
  the strategy/monetization notes before investing in it.
- Authority mode concentrates trust in a forgeable shared STEK (larger blast radius than per-server
  keys) — internal traffic only; state plainly, never hide.

**Neutral**
- East-west / north-south are demoted to pure traffic-direction terms; injectability governs.
- Build order is phased (DESIGN.md §12): Plane 1 inject-one client (v1 demo) → Plane 1 server-side +
  authority → Plane 2 fronting → cluster-wide pooling (only with a measured benchmark).

## Alternatives considered

- **`agent`-only (status quo ante).** Rejected: client-side only; cannot serve a non-PQC or
  certificate-free server.
- **On-path fronting as the primary mechanism.** Rejected: re-invents TLS Lane, forfeits the
  off-path differentiator, and is unnecessary whenever the endpoint is injectable.
- **Keep `router` and `gateway` as distinct components.** Rejected: same role at different dataplane
  layers; distinctness reproduces the prior duplication with no benefit.
