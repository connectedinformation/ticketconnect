// ssl_connect.bpf.c — CO-RE uprobe on SSL_connect entry (DESIGN.md §7 step 1).
//
// Fires before the ClientHello is built. arg0 (rdi) is the SSL*. We emit
// {pid, tid, ssl} to a ring buffer; userspace correlates and drives the ptrace
// install. Detection only — no struct fields are read, nothing is written.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "event.h"

#define SIGSTOP 19

// Opt-in freeze (DESIGN §7 step 1): when set (before load), the probed thread is
// SIGSTOP'd at SSL_connect entry so the injector can install a session before the
// handshake proceeds. Left 0 for detection-only use.
const volatile int freeze = 0;

// Node-wide scan mode attaches a single uprobe to a shared libssl, so it would
// also fire for the agent's own fetch handshakes — and freezing the agent while
// the injector waits on it would deadlock. Exclude by comm (set before load).
const volatile char exclude_comm[16] = {0};

// Report the pid in the injector's OWN pid namespace, not the kernel root ns, so
// /proc and ptrace line up when the injector runs in a nested pid namespace (e.g.
// kind, where hostPID reaches only the node's ns). Set to the injector's
// /proc/self/ns/pid (dev, ino) before load; 0 means "use the root ns".
const volatile __u64 target_pidns_dev = 0;
const volatile __u64 target_pidns_ino = 0;

static __always_inline int excluded(void)
{
    if (exclude_comm[0] == 0) {
        return 0;
    }
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
#pragma unroll
    for (int i = 0; i < 16; ++i) {
        if (exclude_comm[i] == 0) {
            return comm[i] == 0; // exact match up to the terminator
        }
        if (comm[i] != exclude_comm[i]) {
            return 0;
        }
    }
    return 1;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("uprobe/SSL_connect")
int BPF_UPROBE(on_ssl_connect, void* ssl)
{
    if (excluded()) {
        return 0;
    }
    struct ssl_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = (__u32)(id >> 32);
    e->tid = (__u32)id;
    if (target_pidns_ino != 0) {
        struct bpf_pidns_info ns = {0};
        if (bpf_get_ns_current_pid_tgid(target_pidns_dev, target_pidns_ino, &ns, sizeof(ns)) == 0) {
            e->pid = ns.tgid; // pid as seen in the injector's namespace
            e->tid = ns.pid;
        }
    }
    e->ssl = (__u64)ssl;
    bpf_ringbuf_submit(e, 0);

    if (freeze) {
        bpf_send_signal(SIGSTOP); // hold the thread at SSL_connect entry
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
