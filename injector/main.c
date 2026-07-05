// injector — the privileged daemon (DESIGN §5.2). Attaches the eBPF SSL_connect
// uprobe (freeze armed), and for each detected connection pulls a session for the
// configured destination from the agent's UDS and installs it over ptrace, then
// releases the frozen thread. A miss falls back to normal TLS and is logged — no
// silent downgrade.
//
//   injector --agent <sock> --dest <host:port> --pid <N> [--libssl <path>]
//
// v1 is single-destination (the pool's pre-warmed target); SNI-based multi-dest
// lookup is a later refinement.

#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "event.h"
#include "install.h"
#include "ssl_connect.skel.h"
#include "uds.h"

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

struct daemon_ctx {
    const char* agent_sock;
    const char* dest;
};

static int find_libssl_for_pid(pid_t pid, char* out, size_t cap)
{
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE* f = fopen(maps, "r");
    if (!f) {
        return -1;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char path[512] = {0};
        if (sscanf(line, "%*s %*s %*s %*s %*s %511[^\n]", path) == 1 && strstr(path, "libssl.so")) {
            snprintf(out, cap, "%s", path);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int on_event(void* ctx, void* data, size_t len)
{
    struct daemon_ctx* d = ctx;
    if (len < sizeof(struct ssl_event)) {
        return 0;
    }
    const struct ssl_event* e = data;

    unsigned char* der = NULL;
    int der_len = 0;
    int is_pqc = 0;
    char group[64] = {0};
    int status = uds_get(d->agent_sock, d->dest, &der, &der_len, &is_pqc, group, sizeof(group));

    if (status == UDS_STATUS_OK) {
        int rc = inject_session(e->pid, (unsigned long)e->ssl, der, der_len);
        fprintf(stderr, "pid=%u ssl=%#llx dest=%s group=%s -> %s\n", e->pid,
                (unsigned long long)e->ssl, d->dest, group, rc == 0 ? "RESUMED" : "install-failed");
        free(der);
    }
    else {
        // No session: fall back to normal TLS, but surface it (no silent downgrade).
        fprintf(stderr, "pid=%u dest=%s -> MISS, falling back to normal TLS (event)\n", e->pid,
                d->dest);
    }

    kill((pid_t)e->pid, SIGCONT); // always release the frozen thread
    return 0;
}

int main(int argc, char** argv)
{
    const char* agent_sock = NULL;
    const char* dest = NULL;
    const char* libssl = NULL;
    pid_t target = -1;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--agent") && i + 1 < argc) {
            agent_sock = argv[++i];
        }
        else if (!strcmp(argv[i], "--dest") && i + 1 < argc) {
            dest = argv[++i];
        }
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            target = (pid_t)atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--libssl") && i + 1 < argc) {
            libssl = argv[++i];
        }
        else {
            fprintf(stderr,
                    "usage: %s --agent <sock> --dest <host:port> --pid <N> [--libssl <path>]\n",
                    argv[0]);
            return 2;
        }
    }
    if (!agent_sock || !dest || target <= 0) {
        fprintf(stderr, "missing --agent/--dest/--pid\n");
        return 2;
    }

    char libssl_buf[512];
    if (!libssl) {
        if (find_libssl_for_pid(target, libssl_buf, sizeof(libssl_buf)) != 0) {
            fprintf(stderr, "no libssl mapped in pid %d\n", target);
            return 1;
        }
        libssl = libssl_buf;
    }

    struct ssl_connect_bpf* skel = ssl_connect_bpf__open();
    if (!skel) {
        return 1;
    }
    skel->rodata->freeze = 1;
    if (ssl_connect_bpf__load(skel)) {
        fprintf(stderr, "BPF load failed (need CAP_BPF/CAP_PERFMON)\n");
        return 1;
    }

    LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = "SSL_connect");
    skel->links.on_ssl_connect =
        bpf_program__attach_uprobe_opts(skel->progs.on_ssl_connect, target, libssl, 0, &uopts);
    if (!skel->links.on_ssl_connect) {
        fprintf(stderr, "uprobe attach failed on %s\n", libssl);
        ssl_connect_bpf__destroy(skel);
        return 1;
    }

    struct daemon_ctx dctx = {.agent_sock = agent_sock, .dest = dest};
    struct ring_buffer* rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, &dctx, NULL);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "injector: watching pid %d (%s) for dest %s via agent %s\n", target, libssl,
            dest, agent_sock);

    while (g_running) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -4 /* EINTR */) {
            break;
        }
    }

    ring_buffer__free(rb);
    ssl_connect_bpf__destroy(skel);
    return 0;
}
