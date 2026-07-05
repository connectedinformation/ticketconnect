# TicketConnect — Design (v1)

> Working name. Clean-room reimplementation; **no code, docs, or git history imported from the
> pre-2026-04-10 tree.** This document is the specification; the implementation derives from it,
> not from the prior source.

## 1. Thesis

Make the **TLS 1.3 session ticket a programmable session-bootstrap primitive**. A PQC-capable
agent performs the quantum-safe handshake a legacy client cannot, and hands the resulting
resumption session to that client so its *own* connection resumes on a PQC-rooted PSK — **off the
data path, with zero change to the application**.

One sentence: *a legacy TLS client gets post-quantum key material it cannot negotiate itself,
without touching its code, its image, or (in v1) its deployment.*

## 2. Goals

1. **Optimize session establishment via resumption.** Replace full handshakes with PSK resumption
   (no key exchange, no certificate verification on the resumed path) — a latency and, more so, a
   CPU win (asymmetric → symmetric).
2. **Remove the certificate dependency (as a consequence).** In *authority mode* (§6.2) the resumed
   path needs no server certificate. Stated honestly: this does not *remove* trust, it *relocates*
   it into a shared, forgeable STEK — a larger blast radius than per-server keys. Scoped to
   internal / east-west, controlled traffic only.
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

## 3. Non-goals (v1)

- Not an on-path data-plane proxy or service mesh (that is TLS Lane / Istio — do not re-invent).
- OpenSSL / libssl targets only. BoringSSL, Go `crypto/tls`, rustls, NSS, Schannel are out of scope.
- No cluster-wide ticket **pooling** optimization, no SaaS control plane in v1.
- No 0-RTT. (Neither forward-secret nor replay-safe; a TLS audience will call it immediately.)

## 4. Deployment model — DaemonSet (v1 headline)

One privileged node agent that transparently upgrades **already-running, unmodified** processes on
the node — the Cilium/Falco/Tetragon shape. Chosen over a preload-sidecar because it is *faithful to
the thesis*: the mission is "legacy you **cannot** touch," and a sidecar quietly assumes you *can*
edit the deployment (add a volume, set `LD_PRELOAD`) and cannot retrofit a process already running.

Intrusiveness is answered by **open source** — auditability is how this class of node agent earns
adoption. But open source answers *"do I trust your intent?"*, not *"is this safe in prod?"* The
latter is answered by the injection design in §5.

The DaemonSet pod is **two containers, least-privilege split:**

| Container | Privilege | Role |
|---|---|---|
| `ticket-agent` | none | Performs X25519MLKEM768 handshakes (OpenSSL 3.5), holds a small per-destination session pool, refreshes before expiry, serves serialized sessions + provenance over a node-local UDS. All network-facing PQC code lives here, unprivileged. |
| `injector` | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `hostPID` | Runs the eBPF uprobes node-wide; on trigger, fetches a session from `ticket-agent` and performs the public-API-only injection (§5). The only privileged component. |

## 5. Injection mechanism — the safety-critical core

**Split: eBPF for detection/timing (cheap, always-on, node-wide); ptrace for the action (rare,
per-connection).** eBPF cannot invoke userspace functions and `bpf_probe_write_user` is unsafe, so
the *action* needs ptrace; but detection at scale needs eBPF.

**Rule that makes the design defensible: ptrace invokes only *public, exported* OpenSSL APIs — it
never writes a private struct field.** This makes the entire offset-corruption bug class
(the prior design's `pwrite` into `SSL_SESSION` at hardcoded offsets, worsened by container image
diversity) *unrepresentable*. We depend only on the stable exported ABI.

Flow:

1. **eBPF CO-RE uprobe** on `SSL_connect` entry (arg0 = `SSL*`), attached node-wide to libssl
   users. Fires before the ClientHello is built. Reads `SSL*` from the register; emits
   `{pid, tid, ssl_ptr, sni}` and freezes the thread (`bpf_send_signal(SIGSTOP)` or a ptrace stop).
   CO-RE handles kernel-side struct reads; no userspace offsets.
2. **injector** looks up a session for `sni` from `ticket-agent`. None → release, fail-open, emit a
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

## 6. Two operating modes (who owns the STEK decides everything)

The ticket's contents are defined by whoever mints it. That single fact splits the product:

### 6.1 Relay mode (v1) — upstream owns the STEK

`ticket-agent` does a real PQC handshake to the *real* upstream; the **upstream** issues the ticket.
We relay it to the client. Delivers **Goal 1** (resumption + PQC key material). We cannot embed
metadata (the upstream controls the ticket), and the server keeps its certificate (it authenticates
to the agent normally). Provenance is available as **agent attestation** (the agent *knows* it used
ML-KEM and reports it out-of-band) — not yet as portable in-ticket metadata.

Client-side only. No server changes. This is the safe, demonstrable default and the v1 target.

### 6.2 Authority mode (later) — agent/control-plane owns the STEK

A shared STEK is distributed (PQC-protected) to `ticket-agent` and to the servers (server-side STEK
injection, same mechanism, server-side). Now **we mint tickets**: we control the body, so we can
**embed metadata + provenance (Goals 2 & 3)** and drop the certificate on the resumed path. This is
more powerful and more security-loaded (shared-STEK trust concentration, server-side injection, the
ticket becomes a bearer credential). Deferred past v1; documented so v1 doesn't paint into a corner.

## 7. Ticket lifecycle

- TLS 1.3 tickets are effectively single-use per resumption → `ticket-agent` maintains a small pool
  per destination and refreshes before expiry.
- **Cold start:** before a destination's pool is warm, the client connects classically. Pre-warm
  configured destinations; on a miss, fail-open **and emit an event** (Goal: no silent downgrade).
- Bind ticket lifetime ≤ ~50% of STEK rotation interval so a rotation doesn't silently break
  resumption (the prior design's silent-staleness gap).

## 8. Security model (state plainly; the prior docs overclaimed here)

- **Enforce `psk_dhe_ke`.** The resumed key mixes the PQC-rooted PSK with a fresh ephemeral. The
  ephemeral is classical (the legacy client's X25519), but the PSK gates the key and never crosses a
  network hop (agent → client is a node-local UDS), so a harvest-now/decrypt-later attacker who
  breaks the classical ephemeral still lacks the PSK. Quantum-safe **iff** `psk_dhe_ke`; never
  `psk_ke`, never 0-RTT.
- **STEK is the crown jewel (authority mode).** Compromise decrypts *and forges* any client's
  tickets. Encrypt at rest, tight perms, rotate; internal traffic only.
- **Metadata trust = STEK trust.** Metadata is only as trustworthy as the STEK; if it ever carries
  authorization, the ticket is a **bearer token** — theft, replay, revocation all in scope. Design
  for it, don't discover it.
- **Injector TCB.** Root-ish, node-wide, touches process memory — but *only via public APIs on
  verified targets*, fail-closed and fail-open, so the worst case is "no upgrade," not "corrupted
  process." That property is what earns the intrusiveness.

## 9. Boundary vs TLS Lane (hard constraint)

The OSS repo **must not** import TLS Lane's closed code (PQC/handshake/codepoint/parser internals).
`ticket-agent` does its PQC handshake on **stock OpenSSL 3.5** (`SSL_connect` + `SSL_get1_session`),
fully self-contained. This keeps TLS Lane's core closed and the two projects cleanly separable.

## 10. v1 acceptance demo (definition of done)

On a single node (kind or a VM):

1. An **already-running, unmodified** legacy client (OpenSSL 3.0 app looping connections) talks to a
   PQC-capable upstream (OpenSSL 3.5 `s_server` offering X25519MLKEM768).
2. Deploy the DaemonSet. **Without touching the client,** its next connection resumes.
3. `tcpdump` proves the transition: full/classical handshake before → PSK resumption after, on a
   ticket the agent minted from an ML-KEM handshake. Agent attests the ML-KEM provenance.

If an unmodified, already-running process makes that transition, v1 is done. Anything not required
for it is out of v1.

## 11. Open decisions (need your call)

- **Name** — keep `TicketConnect`, or rename to fit the broadened "programmable ticket" scope?
- **License** — Apache-2.0 (prior plan) vs MIT.
- **Repo / org** — fresh clean-room repo; which org.
- **Public from commit 1**, or private-then-flip? (Public-from-start maximizes the "authored fresh,
  in the open, post-quit" provenance story.)

## 12. Deferred / future

- **Preload-sidecar** as a *zero-privilege* alternative mode for deployments you *do* control.
- **Authority mode** (§6.2): server-side STEK injection, minted tickets, metadata, cert-free path.
- Cluster-wide ticket **pooling** (only with a real, measured benchmark — the prior "100x" numbers
  were modeled with nothing deployed).
- Beyond OpenSSL (BoringSSL / Go / rustls).
