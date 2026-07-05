# ADR-0002 — Ship v1 first; server-side/authority is the sanctioned next capability; on-path fronting is gated

Status: Accepted (2026-07-05)

## Context

v1 — Plane 1, client-side injection, relay mode (DESIGN.md §5.2, §8.1) — is built,
proven end to end (host acceptance demo, a real GKE run with 111 consecutive
X25519MLKEM768 resumptions, and wire-level verification that the resumed ticket is
the injected one), and packaged as a publishable, responsibly-documented OSS tool.

The natural question is "what's next," with two candidates on the DESIGN.md §12
build order:

- **Step 2 — server-side injection + authority mode** (Plane 1, off-path):
  install a STEK into a legacy server so it accepts minted tickets; the agent
  mints sessions locally. Unlocks certificate-free east-west, all-legacy pairs
  (neither endpoint speaks PQC), and crypto provenance in tickets.
- **Step 3 — frontdesk + gateway/router** (Plane 2, on-path): terminate/steer
  live connections to serve un-injectable (external) peers.

These sit on opposite sides of the project's defining boundary. ticketconnect is
the **off-path** OSS artifact; TLS Lane is the **on-path** closed engine (see
[[project_monetization_thesis]], [[project_strategy_phase]], DESIGN §11). Step 2
stays off-path. Step 3 is on-path — the closest brush with TLS Lane's territory.

## Decision

1. **Ship v1 first; let real demand drive further capability.** ticketconnect's
   role is a credibility/funnel artifact; it is served by being in the world
   generating signal. Both candidates are real investments better justified by
   pull than by speculation (consistent with "measure before you build" and the
   cut of the prior tree's speculative sprawl).

2. **Server-side injection + authority mode is the sanctioned next capability**
   *when* we build more. It is off-path (on-brand), and it is mostly composition
   of proven parts: the install is the same public-API-only, fail-closed ptrace
   injector pointed at a server `SSL_CTX` via the public `SSL_CTX_set_tlsext_
   ticket_keys` (ctrl 59). The genuinely new work is a detection target for the
   server `SSL_CTX*`, an agent-side ticket minter, and — the real cost —
   **security hardening**, because authority mode makes the shared STEK the crown
   jewel and the ticket a bearer credential (DESIGN §10, §8.2).

3. **The on-path fronting plane (Plane 2) is explicitly gated.** It is not a
   technical "next increment" but a **strategic decision** about whether the open
   project may hold on-path capability that overlaps TLS Lane. It requires a
   deliberate business decision and a re-check of DESIGN §11 *before* any code.
   The trigger is a real un-injectable-peer use case in hand, not roadmap inertia.

## Consequences

- The published v1 stays tightly scoped and honest; scope grows on evidence.
- Step 2, when built, extends the off-path primitive to its full symmetric
  reach without crossing the TLS Lane boundary — but raises the security bar
  (shared-STEK handling, bearer-token ticket semantics).
- Step 3 stays off the default path, preserving the clean "off-path OSS vs
  on-path commercial" separation and ticketconnect's differentiation. The cost is
  that un-injectable (north-south/external) peers remain out of scope until that
  call is made.
- Demand signals map to action: "protect my legacy servers / cert-free east-west"
  → build Step 2; "front my external clients" → open the on-path/TLS-Lane
  boundary conversation.

## Alternatives considered

- **Build Step 3 next (fronting).** Rejected as a default: it crosses the
  off-path/on-path boundary that separates ticketconnect from TLS Lane, and enters
  a crowded, liability-heavy space — a decision to make deliberately, not by
  roadmap momentum.
- **Build Step 2 immediately, before shipping.** Deferred: the mechanism is ready,
  but the security-loaded authority-mode surface is better justified by real
  demand than added pre-launch.
