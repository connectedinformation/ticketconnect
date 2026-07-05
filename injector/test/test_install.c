// Tier 3 (integration) — the real install end to end. A forked child is a real
// libssl client: it builds an SSL, hands its pointer to the parent, and spins.
// The parent (injector) installs a DER session into the child via ptrace + public
// OpenSSL APIs, then releases it; the child SSL_connects and must resume (PSK).
//
// The DER is a genuine session for the same server, fetched by the agent — so
// this exercises the agent -> injector -> resumption pipeline. Needs a PQC
// s_server and the session DER on argv (test/run.sh provides both). Tracing one's
// own child is unprivileged.

#define _GNU_SOURCE

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "install.h"

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
    for (struct addrinfo* ai = list; ai != NULL; ai = ai->ai_next) {
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

// Child: real libssl client that pauses (userspace spin) for injection, then
// connects and reports resumption via exit code (0 = reused).
static void run_victim(const char* host, const char* port, int wfd, volatile int* go)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    int fd = connect_tcp(host, port);
    if (fd < 0) {
        _exit(10);
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    unsigned long ssl_addr = (unsigned long)ssl;
    if (write(wfd, &ssl_addr, sizeof(ssl_addr)) != (ssize_t)sizeof(ssl_addr)) {
        _exit(11);
    }

    while (!*go) { // userspace spin — an interrupt lands on plain code
    }

    if (SSL_connect(ssl) != 1) {
        _exit(12);
    }
    int reused = SSL_session_reused(ssl);
    _exit(reused ? 0 : 2);
}

static unsigned char* read_file(const char* path, size_t* len)
{
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = malloc((size_t)n);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
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
    if (der == NULL || der_len == 0) {
        fprintf(stderr, "cannot read DER %s\n", argv[3]);
        return 2;
    }

    // Shared go-flag and a pipe for the child to hand up its SSL pointer.
    volatile int* go =
        mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *go = 0;
    int pfd[2];
    if (pipe(pfd) != 0) {
        return 3;
    }

    pid_t child = fork();
    if (child == 0) {
        close(pfd[0]);
        run_victim(host, port, pfd[1], go);
        _exit(99); // unreachable
    }
    close(pfd[1]);

    unsigned long ssl_ptr = 0;
    if (read(pfd[0], &ssl_ptr, sizeof(ssl_ptr)) != (ssize_t)sizeof(ssl_ptr)) {
        fprintf(stderr, "did not receive victim SSL pointer\n");
        return 1;
    }
    printf("Tier 3 — real install (victim pid %d, ssl %#lx)\n", child, ssl_ptr);

    int inj = inject_session(child, ssl_ptr, der, der_len);
    printf("  %s : inject_session returned %d\n", inj == 0 ? "ok  " : "FAIL", inj);

    *go = 1; // release the victim into SSL_connect

    int status = 0;
    waitpid(child, &status, 0);
    int reused = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("  %s : victim resumed via PSK (SSL_session_reused)\n", reused ? "ok  " : "FAIL");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        printf("        (victim exit code %d)\n", WEXITSTATUS(status));
    }

    free(der);
    int failed = (inj != 0) || !reused;
    printf("\n%s\n", failed ? "real install: FAIL" : "real install: PASS");
    return failed ? 1 : 0;
}
