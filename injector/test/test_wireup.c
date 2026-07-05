// Tier 3 (capstone) — detect -> freeze -> install -> resume, UNCOOPERATIVE.
//
// The victim never pauses at SSL_connect and never hands over its SSL*. It only
// waits for the probe to be armed (modelling "the DaemonSet was deployed before
// the client started"), then runs SSL_connect straight through. Everything else
// is imposed from outside: the eBPF uprobe freezes it (bpf_send_signal SIGSTOP)
// and supplies the SSL*; the injector installs a session over ptrace; SIGCONT
// releases it; its own handshake resumes on the PSK.
//
// Needs BPF privilege (sudo) and a PQC s_server + session DER (run_wireup.sh).

#define _GNU_SOURCE

#include <linux/types.h>

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <openssl/ssl.h>

#include "event.h"
#include "install.h"
#include "ssl_connect.skel.h"

struct capture {
    __u32 want_pid;
    int got;
    struct ssl_event ev;
};

static int on_event(void* ctx, void* data, size_t len)
{
    struct capture* c = ctx;
    if (len >= sizeof(struct ssl_event)) {
        const struct ssl_event* e = data;
        if (e->pid == c->want_pid) {
            c->ev = *e;
            c->got = 1;
        }
    }
    return 0;
}

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

static int connect_tcp(const char* host, const char* port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* list = NULL;
    if (getaddrinfo(host, port, &hints, &list) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo* ai = list; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(list);
    return fd;
}

// Uncooperative victim: wait until the probe is armed, then a plain SSL_connect.
static void run_victim(const char* host, const char* port, int armfd)
{
    char b;
    if (read(armfd, &b, 1) != 1) {
        _exit(20);
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    int fd = connect_tcp(host, port);
    if (fd < 0) {
        _exit(21);
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) { // frozen here by the uprobe until injected
        _exit(22);
    }
    _exit(SSL_session_reused(ssl) ? 0 : 2);
}

static unsigned char* read_file(const char* path, size_t* len)
{
    FILE* f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <port> <der-file>\n", argv[0]);
        return 2;
    }
    const char* host = argv[1];
    const char* port = argv[2];
    size_t der_len = 0;
    unsigned char* der = read_file(argv[3], &der_len);
    if (!der) {
        fprintf(stderr, "cannot read DER\n");
        return 2;
    }

    char libssl[512];
    if (find_libssl(libssl, sizeof(libssl)) != 0) {
        fprintf(stderr, "no libssl in maps\n");
        return 2;
    }

    struct ssl_connect_bpf* skel = ssl_connect_bpf__open();
    if (!skel) {
        return 1;
    }
    skel->rodata->freeze = 1; // arm the SIGSTOP freeze
    if (ssl_connect_bpf__load(skel)) {
        fprintf(stderr, "load failed (need CAP_BPF; run under sudo)\n");
        return 1;
    }

    int arm[2];
    if (pipe(arm) != 0) {
        return 3;
    }
    pid_t child = fork();
    if (child == 0) {
        close(arm[1]);
        run_victim(host, port, arm[0]);
    }
    close(arm[0]);
    printf("Tier 3 — wire-up (uncooperative victim pid %d)\n", child);

    // Attach the uprobe to the victim only, then arm it.
    LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = "SSL_connect");
    skel->links.on_ssl_connect =
        bpf_program__attach_uprobe_opts(skel->progs.on_ssl_connect, child, libssl, 0, &uopts);
    if (!skel->links.on_ssl_connect) {
        fprintf(stderr, "attach failed\n");
        return 1;
    }

    struct capture cap = {.want_pid = (__u32)child};
    struct ring_buffer* rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, &cap, NULL);

    if (write(arm[1], "go", 1) != 1) { // release the victim
        return 1;
    }

    for (int i = 0; i < 50 && !cap.got; ++i) {
        ring_buffer__poll(rb, 100);
    }

    int fails = 0;
    if (!cap.got) {
        printf("  FAIL : no uprobe event\n");
        fails = 1;
    }
    else {
        printf("  ok   : uprobe captured SSL* %#llx from the kernel\n",
               (unsigned long long)cap.ev.ssl);

        // Confirm the freeze took hold, then install into the frozen victim.
        int st = 0;
        waitpid(child, &st, WUNTRACED);
        if (WIFSTOPPED(st)) {
            printf("  ok   : victim frozen at SSL_connect (SIGSTOP)\n");
        }
        else {
            printf("  FAIL : victim not frozen\n");
            fails = 1;
        }

        int inj = inject_session(child, (unsigned long)cap.ev.ssl, der, der_len);
        printf("  %s : session installed over ptrace\n", inj == 0 ? "ok  " : "FAIL");
        fails |= (inj != 0);

        kill(child, SIGCONT); // release into the (now-primed) handshake
    }

    int st = 0;
    waitpid(child, &st, 0);
    int reused = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("  %s : victim's own SSL_connect resumed via PSK\n", reused ? "ok  " : "FAIL");
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0) {
        printf("        (victim exit %d)\n", WEXITSTATUS(st));
    }
    fails |= !reused;

    ring_buffer__free(rb);
    ssl_connect_bpf__destroy(skel);
    free(der);
    printf("\n%s\n", fails ? "wire-up: FAIL" : "wire-up: PASS");
    return fails ? 1 : 0;
}
