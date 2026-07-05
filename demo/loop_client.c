// loop_client — a plain, injection-unaware TLS client that connects in a loop and
// reports whether each connection was a full handshake or a PSK resumption. It
// stands in for "an already-running, unmodified OpenSSL app looping connections"
// (DESIGN §13). Client session caching is OFF, so it never resumes on its own —
// any resumption is the injector's doing.

#define _GNU_SOURCE

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

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

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <port> <count> [delay-ms]\n", argv[0]);
        return 2;
    }
    const char* host = argv[1];
    const char* port = argv[2];
    int count = atoi(argv[3]);
    int delay_ms = argc > 4 ? atoi(argv[4]) : 700;

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); // never self-resume

    printf("loop_client pid %d -> %s:%s, %d connections\n", getpid(), host, port, count);
    fflush(stdout);

    for (int i = 0; i < count; ++i) {
        int fd = connect_tcp(host, port);
        if (fd < 0) {
            printf("[%2d] connect failed\n", i);
            fflush(stdout);
            usleep(delay_ms * 1000);
            continue;
        }
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) == 1) {
            int reused = SSL_session_reused(ssl);
            const char* g = SSL_get0_group_name(ssl);
            printf("[%2d] %-8s (group %s)\n", i, reused ? "RESUMED" : "full", g ? g : "?");
        }
        else {
            printf("[%2d] handshake failed\n", i);
        }
        fflush(stdout);
        SSL_free(ssl);
        close(fd);
        usleep(delay_ms * 1000);
    }
    SSL_CTX_free(ctx);
    return 0;
}
