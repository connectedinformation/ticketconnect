// Tier 3 — the eBPF detection half. Attach the uprobe to SSL_connect in libssl,
// fork a real libssl victim that calls SSL_connect, and confirm the ring-buffer
// event carries the victim's pid and the exact SSL* it passed. This is what
// replaces the install test's cooperative hand-off: the SSL* now comes from the
// kernel, with no target cooperation.
//
// Needs BPF privilege (CAP_BPF/CAP_PERFMON) — run under sudo. No server needed:
// the uprobe fires on SSL_connect *entry*, before any I/O.

#define _GNU_SOURCE

#include <linux/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

#include "event.h"
#include "ssl_connect.skel.h"

struct capture {
    __u32 want_pid;
    int got;
    struct ssl_event ev;
};

static int on_event(void* ctx, void* data, size_t len)
{
    struct capture* c = ctx;
    if (len < sizeof(struct ssl_event)) {
        return 0;
    }
    const struct ssl_event* e = data;
    if (e->pid == c->want_pid) {
        c->ev = *e;
        c->got = 1;
    }
    return 0;
}

// Find the mapped libssl path in our own maps (we link libssl for the victim).
static int find_libssl(char* out, size_t cap)
{
    FILE* f = fopen("/proc/self/maps", "r");
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

// Victim: real libssl client. Send our SSL* up, then enter SSL_connect (fires the
// uprobe). No server: entry fires before any I/O; the handshake result is moot.
static void run_victim(int wfd)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = SSL_new(ctx);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    SSL_set_fd(ssl, fd);

    unsigned long ssl_addr = (unsigned long)ssl;
    if (write(wfd, &ssl_addr, sizeof(ssl_addr)) != (ssize_t)sizeof(ssl_addr)) {
        _exit(11);
    }
    SSL_connect(ssl); // entry triggers the uprobe; return value irrelevant
    _exit(0);
}

int main(void)
{
    char libssl[512];
    if (find_libssl(libssl, sizeof(libssl)) != 0) {
        fprintf(stderr, "could not locate libssl in our maps\n");
        return 2;
    }
    printf("Tier 3 — eBPF SSL_connect uprobe (libssl: %s)\n", libssl);

    struct ssl_connect_bpf* skel = ssl_connect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "open_and_load failed (need CAP_BPF; run under sudo)\n");
        return 1;
    }

    LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = "SSL_connect", .retprobe = false);
    skel->links.on_ssl_connect =
        bpf_program__attach_uprobe_opts(skel->progs.on_ssl_connect, -1, libssl, 0, &uopts);
    if (!skel->links.on_ssl_connect) {
        fprintf(stderr, "attach_uprobe failed\n");
        ssl_connect_bpf__destroy(skel);
        return 1;
    }

    struct capture cap = {0};
    struct ring_buffer* rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, &cap, NULL);

    int pfd[2];
    if (pipe(pfd) != 0) {
        return 3;
    }
    pid_t child = fork();
    if (child == 0) {
        close(pfd[0]);
        run_victim(pfd[1]);
    }
    close(pfd[1]);

    unsigned long victim_ssl = 0;
    if (read(pfd[0], &victim_ssl, sizeof(victim_ssl)) != (ssize_t)sizeof(victim_ssl)) {
        fprintf(stderr, "no SSL pointer from victim\n");
    }
    cap.want_pid = (__u32)child;

    for (int i = 0; i < 50 && !cap.got; ++i) {
        ring_buffer__poll(rb, 100);
    }
    waitpid(child, NULL, 0);

    int fails = 0;
    if (cap.got) {
        printf("  ok   : uprobe fired for the victim (pid %u, tid %u)\n", cap.ev.pid, cap.ev.tid);
    }
    else {
        printf("  FAIL : no event captured for the victim\n");
        fails = 1;
    }
    if (cap.got && cap.ev.ssl == victim_ssl) {
        printf("  ok   : event SSL* %#llx matches the victim's SSL\n",
               (unsigned long long)cap.ev.ssl);
    }
    else {
        printf("  FAIL : event SSL* %#llx != victim SSL %#lx\n", (unsigned long long)cap.ev.ssl,
               victim_ssl);
        fails = 1;
    }

    ring_buffer__free(rb);
    ssl_connect_bpf__destroy(skel);
    printf("\n%s\n", fails ? "eBPF detection: FAIL" : "eBPF detection: PASS");
    return fails ? 1 : 0;
}
