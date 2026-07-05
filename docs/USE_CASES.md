# Use cases

**Transparent post-quantum (or certificate-free) TLS resumption for workloads you
can't modify** — delivered by a node agent, off the data path. The product is the
off-path session-install primitive; PQC is the marquee use case, not the
mechanism.

Every claim below is scoped to what v1 actually does. Where a capability is
deferred to *authority mode*, it says so.

## Primary: PQC for legacy TLS clients you can't recompile

**The pain (2026).** Post-quantum mandates (CNSA 2.0 timelines, harvest-now-
decrypt-later risk) meet fleets of legacy services on OpenSSL that cannot
negotiate `X25519MLKEM768` and cannot be rebuilt or re-deployed at the pace
required — vendor images, frozen/regulated apps, or fleet-scale coordination.

**The fit.** Where the **upstream is already PQC-capable but the client is not**,
the agent performs the PQC handshake and installs the resulting resumption
session, so the legacy client's *own* connections resume on PQC-derived keys — one
DaemonSet, no image or manifest change. This matches the common transitional state
where gateways/servers are upgraded first and a long tail of legacy clients lags.

**Honest boundary.** v1 (relay mode) sources its PQC from that upstream handshake,
so it upgrades **client → PQC-server** links. If *neither* end speaks PQC, the
agent must mint sessions itself (authority mode, deferred). It is also
resumption-based: the first connection to a cold destination is classical until
the pool warms, and a miss falls back to normal TLS **and emits an event** — no
silent downgrade.

## The same capability, framed for the buyer

- **Harvest-now-decrypt-later reduction (east-west).** For long-lived-secret
  internal traffic, resuming on a PQC-rooted PSK removes the recordable classical
  key exchange from the resumed connections — and the PSK is injected locally,
  never on the wire, so a recording adversary cannot capture it.
- **Compliance / crypto-agility bridge.** A deliberate stopgap: PQC coverage on
  the wire for legacy fleets *now*, while proper endpoint migration happens over
  years. An accelerant, not a replacement for upgrading endpoints.

## Where it goes next (authority mode — deferred)

- **Certificate-free east-west** — install a shared STEK so internal services
  resume without presenting certificates. Stated plainly: this *relocates* trust
  into a forgeable shared STEK (a larger blast radius than per-server keys), so it
  is scoped to internal, controlled traffic only.
- **Crypto provenance / attestation** — a verifiable "this PSK descends from an
  ML-KEM handshake" marker carried in the ticket, for audit evidence.
- **All-legacy pairs** — mint locally and inject *both* ends, covering the case
  where neither endpoint speaks PQC.

## Who it's for, and the differentiator

Platform and security teams with large legacy Kubernetes fleets under PQC
timelines; regulated industries. The differentiator is the **off-path** posture:
no sidecar, no inline proxy, no manifest change — it works on the app's own
socket — plus **public-API-only** injection (the memory-corruption bug class is
unrepresentable) and **fail-closed / no silent downgrade**. That off-path posture
is also what distinguishes it from an *on-path* engine: same problem space,
opposite constraint.

## When *not* to use it

The honest scope that makes the rest credible:

- If you can simply **upgrade the endpoint**, do that — it is cleaner.
  ticketconnect earns its place only when you genuinely **cannot touch the
  workload**.
- Not for non-OpenSSL stacks (Go `crypto/tls`, rustls, BoringSSL, Schannel, NSS),
  statically-linked stripped binaries, or (yet) the all-legacy-pair case; x86-64
  and **experimental** today (see [../README.md](../README.md#status--maturity)).
- It is a privileged node agent — an operations/trust decision, the same class as
  Cilium, Falco, or Tetragon.
