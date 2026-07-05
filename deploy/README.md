# Deployment

Container images and Kubernetes manifests for the ticketconnect DaemonSet, plus a
kind acceptance demo.

## Images

| Image | Dockerfile | Contents |
|---|---|---|
| `ticketconnect/agent` | `Dockerfile.agent` | `ticket-agent` (unprivileged authority) |
| `ticketconnect/injector` | `Dockerfile.injector` | `injector` (eBPF + ptrace; CO-RE, needs node BTF) |
| `ticketconnect/demo` | `Dockerfile.demo` | PQC `s_server` + the looping `loop_client` |

The injector image compiles the BPF object against a pre-generated `bpf/vmlinux.h`
(run `make -C bpf vmlinux.h` first) and relocates at load time against the node's
own BTF — so one image runs across kernels.

## Manifests

- `k8s/daemonset.yaml` — the product: namespace + the two-container DaemonSet.
  `hostPID: true` so the injector can see and ptrace processes node-wide; the
  injector container is `privileged` (CAP_BPF / CAP_PERFMON / CAP_SYS_PTRACE); the
  agent is unprivileged. They share the node-local UDS through an `emptyDir`.
- `k8s/demo.yaml` — a single-replica PQC server (one STEK, so tickets resume) and
  an unmodified looping client. Neither is part of ticketconnect.

## Acceptance demo (kind)

```
./run_kind_demo.sh          # build + load + deploy + observe
./run_kind_demo.sh clean    # tear down
```

Expected in the client log: the first connections are `full` handshakes, then —
without any change to the client — its connections become `RESUMED` on
`X25519MLKEM768`, as the injector installs sessions the agent fetched. This is the
DESIGN §13 definition of done.

### Status

The **host demo (`../demo/run_host_demo.sh`) is the proven acceptance test** — the
real agent + injector daemons drive an unmodified looping client from `full` to
`RESUMED`. On kind, the DaemonSet deploys and rolls out, and node-wide detection,
the SIGSTOP freeze, the process scanner (incl. libssl image diversity), and the
agent's pool/UDS all work in-cluster. Two kind-*environment* wrinkles are still
being ironed out and are **not** ticketconnect defects:

- **Nested PID namespaces.** kind nests the node in its own PID namespace, so the
  eBPF event pid (kernel root ns) and the injector's `hostPID` view (node ns)
  differ. Handled with `bpf_get_ns_current_pid_tgid` (report pids in the
  injector's namespace). On a standard node — where `hostPID` *is* the root PID
  namespace — this is a no-op and the pids line up directly.
- **Cluster DNS / startup timing.** The agent's pool now refills on demand (it no
  longer depends on DNS being ready at startup), and `uds_get` has a bounded
  timeout, so a cold start self-heals rather than wedging.

## Security notes

- The injector's node-wide uprobe excludes the agent by comm (`--exclude-comm
  ticket-agent`) — probing the agent's own fetch handshakes would deadlock.
- A miss (empty pool / no session) falls back to normal TLS and is logged — no
  silent downgrade (DESIGN §10).
- The injector installs sessions via public OpenSSL APIs only; a failure leaves
  the target running and uncorrupted ("worst case is no upgrade").
