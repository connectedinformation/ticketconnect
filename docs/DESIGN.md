# TicketConnect — Design (v1)

> Working name. This document is the specification; the implementation derives from it.

## 1. Thesis

Make the **TLS 1.3 session ticket a programmable session-bootstrap primitive**. An agent performs
the handshake a legacy endpoint cannot (or need not) perform for itself, and installs the resulting
resumption session into that endpoint so its *own* next connection resumes on a PQC-rooted,
certificate-free PSK — **off the data path, with zero change to the application**.

The engineering substance is the **off-path session-acquisition-and-injection primitive**, not the
cryptography: stock OpenSSL 3.5 supplies X25519MLKEM768 for free, and once a session exists the
connection is ordinary TLS 1.3 PSK resumption. PQC is the marquee *use case*, not the product.

One sentence: *a legacy TLS endpoint gets post-quantum key material — or a certificate-free resumed
path — it cannot negotiate itself, without touching its code, its image, or (in v1) its deployment.*

The primitive is **symmetric**: the same machinery installs a session into a *client* (so it
resumes outbound) or a STEK into a *server* (so it accepts a minted ticket). §3 names the terms;
§5 gives the one architecture that covers both.

## 2. Goals

The unifying goal is **always resume, on both sides of the connection.** A PSK-resumed TLS 1.3
connection drops *both* the wire key-exchange *and* the certificate from the resumed path, which is
why resumption is the universal substrate for two independent drivers: an endpoint that **cannot
negotiate PQC**, and an endpoint that **has no — or needs no — certificate and private key**.

1. **Optimize session establishment via resumption.** Replace full handshakes with PSK resumption
   (no key exchange, no certificate verification on the resumed path) — a latency and, more so, a
   CPU win (asymmetric → symmetric).
2. **Remove the certificate dependency (as a consequence).** In *authority mode* (§8.2) the resumed
   path needs no server certificate. Stated honestly: this does not *remove* trust, it *relocates*
   it into a shared, forgeable STEK — a larger blast radius than per-server keys. Scoped to
   internal, controlled traffic only.
3. **Attach metadata to the session ticket.** When we mint the ticket (authority mode) its
   STEK-sealed body can carry operator-defined data: routing, tenant, policy, and — the flagship
   use — **crypto provenance** ("this PSK descends from an X25519MLKEM768 handshake"), so a resumed
   connection inherits a verifiable PQC marker.

### Design goals (properties, not features — non-negotiable)

- **Transparency.** No application code change, no image rebuild. In v1 (DaemonSet) not even a
  manifest change.
- **No silent downgrade.** If a ticket is stale/absent or resumption fails, the connection falls
  back to normal TLS *and the event is surfaced*. Silent fallback to classical was the prior
  design's worst security smell; "you always know what you got" is a first-class goal.

## 3. Terminology (say it once, use it everywhere)

The variable that decides the mechanism is **injectability** — can we `ptrace` the endpoint's
process? — *not* compass direction. Name deployments by how many endpoints we can reach:

| Term | Meaning | Delivery |
|---|---|---|
| **inject-both** | both endpoints' processes reachable (typ. same node/cluster) | off-path injection, both ends |
| **inject-one** | exactly one endpoint reachable | off-path injection, the reachable end resumes |
| **inject-none** | neither reachable (external ↔ external) | on-path fronting (terminate + issue) |

**East-west / north-south** are reserved for their literal traffic-direction meaning
(service-to-service vs crossing the cluster boundary) and are **never** used as a proxy for
injectability — they come apart: a north-south *egress* connection (your pod → external API) is
inject-one on the client side, while a cross-cluster east-west connection may be inject-one or
inject-none.

## 4. Non-goals (v1)

- Not a general on-path traffic proxy or service mesh for arbitrary data-plane interception (that is
  an inline proxy / service-mesh problem, e.g. Istio — do not re-invent). The **fronting plane**
  (§5.3) terminates a handshake *only*
  to issue a ticket for an un-injectable peer; it is a bounded ticket issuer, not a traffic splicer,
  and its build is gated behind the off-path core.
- OpenSSL / libssl targets only. BoringSSL, Go `crypto/tls`, rustls, NSS, Schannel are out of scope.
- No cluster-wide ticket **pooling** optimization, no SaaS control plane in v1.
- No 0-RTT. (Neither forward-secret nor replay-safe; a TLS audience will call it immediately.)

## 5. Architecture — one authority, two delivery planes

Four components, but not four peers: **one authority** for session material, delivered by **two
planes**. The unifying fact is the **shared STEK** — the agent is the single source of truth, and
whether that material reaches an endpoint by *injection* (off-path) or by *terminating its
handshake* (on-path) is only a delivery choice. Because both planes seal under the same STEK, a
ticket the frontdesk mints for an external client is decryptable by an agent-injected server, and
vice versa.

```
                    ┌─────────────────────────────────────┐
                    │  AGENT  (session/ticket authority)   │
                    │  • relay:  outbound handshake         │
                    │  • mint:   PSK + STEK-sealed ticket    │
                    │  • POOL:   per-destination inventory   │
                    │  → one shared STEK feeds both planes   │
                    └───────────────┬─────────────────────┘
                    off-path         │          on-path
              ┌──────────────────────┴──────────────────────┐
              ▼                                              ▼
   PLANE 1 — INJECTION (§5.2)                 PLANE 2 — FRONTING (§5.3)
   ┌──────────────────┐                       ┌──────────────────────┐
   │ INJECTOR (ptrace)│                       │ GATEWAY  (front door) │
   │  client ← session│                       │  steer by ClientHello │
   │  server ← STEK   │                       │   has PSK → backend   │
   └──────────────────┘                       │   PQC,no PSK→frontdesk│
   for inject-both / inject-one               └──────────┬───────────┘
                                                         ▼
                                              ┌──────────────────────┐
                                              │ FRONTDESK (TLS term.) │
                                              │  mint ticket for an   │
                                              │  un-injectable peer   │
                                              └──────────────────────┘
                                              for inject-none
```

### 5.1 The authority — `agent` (+ the pool)

`agent` is the source of truth for session material, and the **pool** is its inventory. Two sourcing
modes feed the pool: **relay** (a real outbound handshake — inherits the upstream's ticket and PQC)
and **mint** (generate a PSK, seal a ticket under a locally-held STEK, tag provenance/metadata).

The pool sits **between sourcing and delivery** and exists because injection is *event-driven*: the
uprobe fires the instant a client calls `SSL_connect`, and sourcing a session on demand there would
bolt a full handshake onto the client's own latency. The pool decouples them — sourcing runs ahead
in the background, delivery is an instant lookup. TLS 1.3 tickets are single-use per resumption, so
the pool keeps **depth per destination**. The pool is **plane-agnostic**: the injector pulls from it
(Plane 1) and the frontdesk draws on the same authority/STEK (Plane 2). Pool warmth *is* the hit
rate, and every miss is exactly the event the no-silent-downgrade invariant requires.

Sourcing mode sets the pool's economics: **relay** refills cost a real PQC handshake and are bounded
by the upstream's STEK rotation (see §9); **mint** refills are local, cheap, and self-lifetimed — so
authority mode is what keeps deep pools warm for free, an argument for it independent of the
cert-free story. (Relay's STEK-rotation bound on ticket lifetime is in §9.)

### 5.2 Plane 1 — injection (off-path). Components: `agent` + `injector`

For **reachable** endpoints (inject-both, inject-one). The `injector` `ptrace`-installs into whichever
end(s) we can reach — a session into a client (`SSL_set_session` → resumes outbound) or a STEK into a
server (accepts minted tickets). Client and server then connect **directly**; nothing sits on the
data path. This is the headline capability and the v1 build target. Mechanism detail in §7.

### 5.3 Plane 2 — fronting (on-path). Components: `gateway` + `frontdesk`

For **un-injectable** endpoints (inject-none) — an external browser, a partner server, anything we
cannot `ptrace`. Here the material cannot be injected, so it must be *served*:

- **`gateway`** — the front door. Inspects the ClientHello and steers: has a PSK/ticket → legacy
  backend (resumption); offers PQC groups but no ticket → `frontdesk`; neither → legacy backend
  (classical) **and emits an event** (no silent downgrade). Its dataplane is an implementation
  choice — userspace proxy first, sockmap/XDP as later acceleration — **not** four separate
  components. A ClientHello steerer is one role; splitting it per dataplane layer is a defect to
  avoid. See ADR-0001.
- **`frontdesk`** — a real TLS 1.3 endpoint that terminates the un-injectable peer's handshake and
  issues a ticket sealed under the shared STEK; the peer then resumes against a backend that holds
  the same STEK (installed off-path by the injector, or pre-shared).

This plane **is** on the data path — the consciously-scoped, TLS-Lane-adjacent tier. It exists in
the architecture so v1 does not paint into a corner, but its **build is deferred and gated behind
the off-path core** (§12).

### 5.4 Component roster, privilege, packaging

| Component | Plane | Role | Privilege | Packaging |
|---|---|---|---|---|
| `agent` | authority | source/mint sessions, own the STEK, hold the pool | none | DaemonSet |
| `injector` | 1 (off-path) | `ptrace`-install session (client) or STEK (server) | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `hostPID` | DaemonSet |
| `gateway` | 2 (on-path) | ClientHello front door + routing | network only | Deployment/Service |
| `frontdesk` | 2 (on-path) | PQC-terminating ticket issuer for un-injectable peers | network only | Deployment/Service |

The packaging split falls out of the planes: the off-path plane is a **node agent (DaemonSet)**; the
on-path plane is a **network endpoint (Deployment + Service)** — different privilege, different
lifecycle, not the same pod. The component holding key material (`agent`) is unprivileged and
network-facing; the privileged component (`injector`) holds no long-term secret and only pulls from
the pool and installs. Regime → components: **inject-both / inject-one** → `agent` + `injector`;
**inject-none** → `agent` (authority) + `gateway` + `frontdesk`.

## 6. Deployment model — DaemonSet (v1 headline)

One privileged node agent that transparently upgrades **already-running, unmodified** processes on
the node — the Cilium/Falco/Tetragon shape. Chosen over a preload-sidecar because it is *faithful to
the thesis*: the mission is "legacy you **cannot** touch," and a sidecar quietly assumes you *can*
edit the deployment (add a volume, set `LD_PRELOAD`) and cannot retrofit a process already running.

Intrusiveness is answered by **open source** — auditability is how this class of node agent earns
adoption. But open source answers *"do I trust your intent?"*, not *"is this safe in prod?"* The
latter is answered by the injection design in §7.

The DaemonSet pod is the off-path plane's **two containers, least-privilege split** — `agent`
(unprivileged) and `injector` (privileged) per §5.4.

## 7. Injection mechanism — the safety-critical core

**Split: eBPF for detection/timing (cheap, always-on, node-wide); ptrace for the action (rare,
per-connection).** eBPF cannot invoke userspace functions and `bpf_probe_write_user` is unsafe, so
the *action* needs ptrace; but detection at scale needs eBPF.

**Rule that makes the design defensible: ptrace invokes only *public, exported* OpenSSL APIs — it
never writes a private struct field.** This makes the entire offset-corruption bug class
(the prior design's `pwrite` into `SSL_SESSION` at hardcoded offsets, worsened by container image
diversity) *unrepresentable*. We depend only on the stable exported ABI.

Flow (client-side session install; server-side STEK install is the mirror — same technique, public
`SSL_CTX` APIs on a verified server target):

1. **eBPF CO-RE uprobe** on `SSL_connect` entry (arg0 = `SSL*`), attached node-wide to libssl
   users. Fires before the ClientHello is built. Reads `SSL*` from the register; emits
   `{pid, tid, ssl_ptr, sni}` and freezes the thread (`bpf_send_signal(SIGSTOP)` or a ptrace stop).
   CO-RE handles kernel-side struct reads; no userspace offsets.
2. **injector** looks up a session for `sni` from `agent`. None → release, fail-open, emit a
   `no_ticket` event (no silent downgrade).
3. `PTRACE_SEIZE` the thread (`PTRACE_O_EXITKILL` set, whole-thread-group aware).
4. Remote `mmap` (public syscall — offset-free) a scratch buffer in the target.
5. `process_vm_writev` the serialized session DER into that buffer (writing to a buffer *we*
   allocated — no target-layout knowledge).
6. Remote-call **`d2i_SSL_SESSION`** (exported) → materializes the `SSL_SESSION` in the target heap.
7. Remote-call **`SSL_set_session(ssl_ptr, sess)`** (exported), then **`SSL_SESSION_free`**.
8. Detach. The target proceeds into `SSL_connect` and resumes on the PQC-rooted PSK.

Symbol addresses resolve from the target's `/proc/pid/maps` base + the library's **dynsym** (stable
ABI), never from private-struct offset tables. Remote function-call setup (registers, stack, return
trap) is generic and offset-independent — the well-trodden `gdb call` / Frida technique.

**Fail-closed guards:** unknown/uncertain target → skip, never poke. Verify the resolved symbol set
before any call. `PTRACE_O_EXITKILL` so a dead agent never leaves a process stopped.

## 8. Two operating modes (who owns the STEK decides everything)

The ticket's contents are defined by whoever mints it. That single fact splits the product, and it
maps onto the planes: relay is the safe client-side default; authority is what unlocks server-side
injection and the fronting plane.

### 8.1 Relay mode (v1) — upstream owns the STEK

`agent` does a real PQC handshake to the *real* upstream; the **upstream** issues the ticket.
We relay it to the client. Delivers **Goal 1** (resumption + PQC key material). We cannot embed
metadata (the upstream controls the ticket), and the server keeps its certificate (it authenticates
to the agent normally). Provenance is available as **agent attestation** (the agent *knows* it used
ML-KEM and reports it out-of-band) — not yet as portable in-ticket metadata.

Client-side only (inject-one, client). No server changes. The safe, demonstrable default and the v1
target.

### 8.2 Authority mode (later) — agent/control-plane owns the STEK

A shared STEK is distributed (PQC-protected) to `agent` and to the servers (server-side STEK
injection via Plane 1, or `frontdesk` serving it via Plane 2). Now **we mint tickets**: we control
the body, so we can **embed metadata + provenance (Goals 2 & 3)** and drop the certificate on the
resumed path. This is what makes inject-both, server-side inject-one, and the whole fronting plane
possible — and it is more security-loaded (shared-STEK trust concentration, the ticket becomes a
bearer credential). Deferred past v1; documented so v1 doesn't paint into a corner.

## 9. Ticket lifecycle

- TLS 1.3 tickets are effectively single-use per resumption → the `agent` pool (§5.1) maintains
  depth per destination and refreshes before expiry.
- **Cold start:** before a destination's pool is warm, the client connects classically. Pre-warm
  configured destinations; on a miss, fail-open **and emit an event** (Goal: no silent downgrade).
- Bind ticket lifetime ≤ ~50% of STEK rotation interval so a rotation doesn't silently break
  resumption (the prior design's silent-staleness gap).

## 10. Security model (state plainly; the prior docs overclaimed here)

- **Enforce `psk_dhe_ke`.** The resumed key mixes the PQC-rooted PSK with a fresh ephemeral. The
  ephemeral is classical (the legacy client's X25519), but the PSK gates the key and never crosses a
  network hop (agent → client is a node-local UDS, and a self-minted PSK is installed locally by
  ptrace), so a harvest-now/decrypt-later attacker who breaks the classical ephemeral still lacks
  the PSK. Quantum-safe **iff** `psk_dhe_ke`; never `psk_ke`, never 0-RTT.
- **STEK is the crown jewel (authority mode).** Compromise decrypts *and forges* any client's
  tickets. Encrypt at rest, tight perms, rotate; internal traffic only.
- **Metadata trust = STEK trust.** Metadata is only as trustworthy as the STEK; if it ever carries
  authorization, the ticket is a **bearer token** — theft, replay, revocation all in scope. Design
  for it, don't discover it.
- **Server injection is not risk-symmetric with client injection.** A client gets a one-shot session
  before it initiates a connection; a server gets a long-lived shared STEK and will then accept *any*
  ticket sealed under it, on a process actively serving live traffic. Same mechanism, larger blast
  radius — treat server-side install with the authority-mode STEK cautions, not the relay defaults.
- **Fronting plane invariants (Plane 2).** The `gateway` must emit an event on any classical
  fallback (no silent downgrade), and the `frontdesk`'s shared STEK carries the trust-concentration
  caveat above — stated plainly, never hidden.
- **Injector TCB.** Root-ish, node-wide, touches process memory — but *only via public APIs on
  verified targets*, fail-closed and fail-open, so the worst case is "no upgrade," not "corrupted
  process." That property is what earns the intrusiveness.

## 11. Off-path boundary (hard constraint)

ticketconnect stays **off the data path**. `agent` does its PQC handshake on **stock OpenSSL 3.5**
(`SSL_connect` + `SSL_get1_session`), fully self-contained — it depends on no inline/on-path engine.
The on-path fronting plane (§5.3) is the closest brush with an on-path posture; it stays bounded (it
issues tickets, it does not splice arbitrary traffic) and its build is gated — re-check this boundary
before investing in it.

## 12. Build order (phased)

1. **Plane 1, inject-one (client), relay mode** — the v1 acceptance demo (§13). The off-path
   primitive, client side, no minting.
2. **Plane 1, server-side injection + authority mode** — mint locally, install STEK into a reachable
   server; unlocks inject-both and inject-one (server). Off-path, symmetric.
3. **Plane 2, fronting (`gateway` + `frontdesk`)** — inject-none, on-path. Gated behind 1–2 and a
   re-check of §11.
4. **Cluster-wide pooling** — only with a real, measured benchmark (the prior "100x" numbers were
   modeled with nothing deployed). Slots in as a tier-2 cache behind the per-node pool (§5.1).

> Sequencing/gating: v1 (step 1) ships first and demand drives the rest. Step 2 (server-side +
> authority) is the sanctioned next capability (off-path, security-loaded); step 3 (on-path fronting)
> is gated behind a deliberate strategic decision on the off-path boundary (§11), not roadmap inertia.
> See [`adr/0002-roadmap-ship-first-server-support-gate-fronting.md`](adr/0002-roadmap-ship-first-server-support-gate-fronting.md).

## 13. v1 acceptance demo (definition of done)

On a single node (kind or a VM), exercising **step 1 of §12** (Plane 1, inject-one client, relay):

1. An **already-running, unmodified** legacy client (OpenSSL 3.0 app looping connections) talks to a
   PQC-capable upstream (OpenSSL 3.5 `s_server` offering X25519MLKEM768).
2. Deploy the DaemonSet. **Without touching the client,** its next connection resumes.
3. `tcpdump` proves the transition: full/classical handshake before → PSK resumption after, on a
   ticket the agent relayed from an ML-KEM handshake. Agent attests the ML-KEM provenance.

If an unmodified, already-running process makes that transition, v1 is done. Anything not required
for it is out of v1.

## 14. Deferred / future

- **Preload-sidecar** as a *zero-privilege* alternative mode for deployments you *do* control.
- Beyond OpenSSL (BoringSSL / Go / rustls).

(Authority mode, the fronting plane, and cluster-wide pooling are on the phased roadmap in §12, not
here — they are planned, not merely speculative.)
