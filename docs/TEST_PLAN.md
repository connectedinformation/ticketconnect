# TicketConnect — Test Plan

Companion to [DESIGN.md](DESIGN.md). Tests are organized by **blast radius**, and
the security invariants (DESIGN §10) are exercised as **negative paths** — the
prior prototype's worst failures were silent downgrade, a false integrity claim,
memory corruption, and a threading race, all of which a happy-path suite misses.

## Two principles

1. **Invariants get negative tests, first-class.** Each invariant in DESIGN §10 has
   a test that *forces the bad condition* and asserts the safe outcome — not a
   happy-path test that merely happens to pass.
2. **The property to prove hardest: "worst case is no upgrade, never a corrupted
   process."** That property is what earns the injector's privilege, so it gets the
   most adversarial coverage (image diversity, chaos, fail-closed).

## Tiers (by privilege / blast radius)

### Tier 1 — unit / component (unprivileged, fast, every CI run)

- **Session source**: handshake against a local `s_server`; assert negotiated
  group, session captured, `i2d`∘`d2i` round-trips to an identical resumable
  session, provenance flag correct.
- **Pool** (when built): depth/eviction, single-use consumption, refresh before
  expiry, cold-start miss path.
- **UDS protocol** (when built): framing; malformed-input rejection.
- **Group policy**: `psk_dhe_ke` enforced; `psk_ke` rejected; 0-RTT never offered.

### Tier 2 — injection payload (userspace, no ptrace)

`d2i_SSL_SESSION` + `SSL_set_session` in-process, then assert
`SSL_session_reused() == 1` and the resumed group is correct. Validates the
*payload* independently of delivery, so a Tier 3 failure localizes to the ptrace
harness, not the session.

### Tier 3 — injector mechanism (privileged; VM / privileged runner)

- **ptrace remote-call harness** against a victim we spawn: remote `mmap` →
  `process_vm_writev` → remote `d2i`/`SSL_set_session`; assert the victim resumes.
- **eBPF uprobe**: attach to a test binary calling `SSL_connect`; assert the
  `{pid, tid, ssl_ptr, sni}` event is correct.
- **Fail-closed**: unverified target → skipped, never poked; symbol-resolution
  failure → aborts *before* any write; `PTRACE_O_EXITKILL` → killing the agent
  mid-injection leaves the target alive and unstopped.

### Tier 4 — end-to-end / acceptance (kind or VM)

The DESIGN §13 definition of done: an unmodified, already-running OpenSSL 3.0
client looping connections to a PQC upstream; deploy the DaemonSet; assert the
full→resumption transition. Build-order step 2 adds the server-side-injection E2E.

## Cross-cutting (across tiers)

- **Invariant negatives**: force an empty/stale pool and a resumption failure →
  assert classical fallback **and that the event fired** (the event is the
  assertion). Assert `psk_ke`/0-RTT never appear on the wire.
- **Wire-level evidence, not just asserts**: `tcpdump` + `SSLKEYLOGFILE` decode to
  *show* classical-before / PSK-resume-after; `s_client -trace` to confirm the
  `0x11EC` X25519MLKEM768 codepoint on the agent's handshake.
- **Image diversity** (where the prior design broke): run the injector against
  several libssl versions/images; every case injects *or* fails closed — never
  corrupts.
- **Concurrency / chaos**: multi-threaded target (the prior single-thread-stop
  race), target exits mid-ptrace, agent crash mid-injection, malformed tickets.
- **Sanitizers**: ASan/UBSan builds for userspace; `clang-format --dry-run` gate.

## CI shape

| Tier | Runner | When |
|---|---|---|
| 1–2 | ordinary CI (unprivileged) | every push |
| 3 | privileged runner / Fedora VM w/ real kernel | pre-merge |
| 4 | kind cluster | pre-merge / nightly |

## Mapping to build order (DESIGN §12)

Each increment ships with its tests:

1. **Plane 1, inject-one client, relay** → Tier 1 (session source) + Tier 2
   (resume round-trip) + Tier 4 golden path.
2. **Plane 1, server inject + authority** → STEK-handling unit tests, server-side
   E2E, STEK at-rest/rotation checks.
3. **Plane 2, fronting** → gateway ClientHello-routing tests + the gateway's own
   no-silent-downgrade negative test.
4. **Cluster-wide pooling** → only with the measured benchmark that gates it.

## Current state

Tiers 1–2 are wired for the agent's authority role (`ticket-agent/test/`, run via
`make -C ticket-agent check`):

- **Hermetic (no network):** `test_pool` covers the pool — maintain-to-depth,
  single-use `get`, cold-start miss, expiry eviction, source-failure tolerance —
  with an injected fake source. `test_uds` covers the UDS protocol parser's
  malformed-input rejection (bad magic/version/op, length mismatch, empty dest).
- **Network:** `test_session` fetches from a local PQC `s_server` and asserts
  group / resumability / DER round-trip, then resumes to prove
  `SSL_session_reused()`. The runner then starts the agent's `serve` (pre-warmed
  pool over a Unix socket) and a `get` client, and confirms the UDS-delivered
  bytes are a real resumable session (`Resumption PSK` present).

Tier 3 is up through the real install (`make -C injector check`, all unprivileged
— each traces its own child):

- `test_remote` — the ptrace remote-call primitive (call `getpid()` in a child,
  check the return, repeat to confirm the target is restored intact).
- `test_symbols` — runtime `.dynsym` resolution (resolve `getpid`/`mmap`, call the
  resolved `getpid`, resolve across a forked target, fail closed on unknowns).
- `test_install` — the **real install end to end**: the agent fetches a genuine
  session, the injector installs it into a live libssl victim via public APIs
  (remote `mmap` → `process_vm_writev` → `d2i_SSL_SESSION` → `SSL_set_session` →
  `SSL_SESSION_free`), and the victim's `SSL_connect` resumes (`SSL_session_reused`).

- `bpf/test/test_detect` — the **eBPF `SSL_connect` uprobe**: attach CO-RE, fork a
  real libssl victim, and confirm the ring-buffer event carries the victim's pid
  and the exact `SSL*` it passed — the kernel supplies what the install test used
  to hand off cooperatively. Needs BPF privilege (`make -C bpf check` runs it
  under sudo).

- `injector/test/test_wireup` — the **capstone**, fully uncooperative: the uprobe
  (freeze armed) SIGSTOPs the victim at `SSL_connect` and hands its `SSL*` up from
  the kernel; the injector installs a session over ptrace; `SIGCONT` releases it;
  its *own* `SSL_connect` resumes on the PSK. The victim never pauses at the call
  or hands off its pointer. Needs BPF privilege (`make -C injector check-wireup`).

- `injector/test/test_failclosed` — the **fail-closed negatives** (DESIGN §7):
  unresolved symbol set → never seized, target alive; garbage DER → `d2i` rejects
  it, victim uncorrupted (exits cleanly); `PTRACE_O_EXITKILL` → a tracer that dies
  mid-injection gets the target SIGKILLed, not left stopped. Unprivileged.

Tier 4 has begun on the host: `demo/run_host_demo.sh` runs the real `ticket-agent
serve` + `injector` daemons against an **unmodified looping client** and shows the
transition — full handshakes before the injector is deployed, PSK resumption
(X25519MLKEM768) after, with no change to the client (DESIGN §13, pre-k8s).

The injector now has a **node-wide scan mode** (`--scan`) for the DaemonSet:
discover every process with libssl mapped, attach one uprobe per distinct libssl
file, and exclude the agent by comm in BPF (probing its own fetch handshakes would
deadlock). Discovery is verified safely with `--dry-run` (no BPF, no freeze).

**Tier 4 packaging** (`deploy/`) is built: three container images (all build),
the two-container DaemonSet, demo manifests, and `run_kind_demo.sh`. The **host
demo is the proven acceptance test**; on kind the DaemonSet deploys with node-wide
detection, freeze, scan (incl. image diversity), and pool/UDS all working — two
kind-environment wrinkles (nested PID namespace, cluster DNS timing) are handled /
documented in `deploy/README.md` and are no-ops on a standard node.

**Proven on real Kubernetes:** `deploy/gke/run_gke_demo.sh` ran the DaemonSet on a
GKE Standard node (Ubuntu, kernel 6.8) and an unmodified looping client resumed on
X25519MLKEM768 for **111 consecutive connections** — the full detect → freeze →
install → resume flow, end to end, in a real cluster. kind's nested PID namespace
is confirmed as the only blocker there and is absent on a standard node.

Node-wide uprobes are deduped by a container-stable `name_to_handle_at` file
handle (not `st_dev`+inode), so a libssl shared across pods is probed exactly once
(no benign double-inject).
