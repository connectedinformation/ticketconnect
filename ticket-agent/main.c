// ticket-agent — CLI (v1). Subcommands:
//   fetch <host> <port> [-k] [-o <der>]   one-shot: handshake + capture a session
//   serve <sock> <host:port>... [-k] [--depth N]   pre-warm a pool, serve over UDS
//   get   <sock> <host:port> [-o <der>]   client: request a session from the agent
//
// Reusable logic lives in session_source.{c,h} (source), pool.{c,h} (inventory),
// and uds.{c,h} (protocol). This binary is the authority component (DESIGN §5.1).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "pool.h"
#include "session_source.h"
#include "uds.h"

struct Live_ctx {
    int insecure;
};

// Split "host:port" on the last ':'. Returns 0 on success.
static int split_dest(const char* dest, char* host, size_t host_cap, const char** port)
{
    const char* colon = strrchr(dest, ':');
    if (colon == NULL || colon == dest || colon[1] == '\0') {
        return -1;
    }
    size_t host_len = (size_t)(colon - dest);
    if (host_len + 1 > host_cap) {
        return -1;
    }
    memcpy(host, dest, host_len);
    host[host_len] = '\0';
    *port = colon + 1;
    return 0;
}

// Pool_source_fn: the live upstream. Handshake, serialize, hand the DER to the pool.
static int live_source(void* ctx, const char* dest, unsigned char** der, int* der_len, int* is_pqc,
                       char* group, size_t group_cap, long* lifetime_s)
{
    struct Live_ctx* lc = ctx;
    char host[256];
    const char* port = NULL;
    if (split_dest(dest, host, sizeof(host), &port) != 0) {
        return 1;
    }

    struct Fetch_result r;
    if (session_fetch(host, port, lc->insecure, &r) != 0) {
        return 1;
    }
    int n = session_to_der(r.session, der);
    if (n <= 0) {
        SSL_SESSION_free(r.session);
        return 1;
    }
    *der_len = n;
    *is_pqc = r.is_pqc;
    snprintf(group, group_cap, "%s", r.group);
    *lifetime_s = (long)SSL_SESSION_get_timeout(r.session);
    SSL_SESSION_free(r.session);
    return 0;
}

static void usage(const char* argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s fetch <host> <port> [-k] [-o <der-file>]\n"
            "  %s serve <sock> <host:port>... [-k] [--depth N]\n"
            "  %s get   <sock> <host:port> [-o <der-file>]\n",
            argv0, argv0, argv0);
}

static int write_der(const char* path, const unsigned char* der, int der_len)
{
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "cannot write %s\n", path);
        return -1;
    }
    fwrite(der, 1, (size_t)der_len, f);
    fclose(f);
    printf("wrote       : %s\n", path);
    return 0;
}

static int cmd_fetch(int argc, char** argv)
{
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }
    const char* host = argv[2];
    const char* port = argv[3];
    int insecure = 0;
    const char* der_out = NULL;
    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "-k") == 0) {
            insecure = 1;
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            der_out = argv[++i];
        }
        else {
            usage(argv[0]);
            return 2;
        }
    }

    struct Fetch_result result;
    if (session_fetch(host, port, insecure, &result) != 0) {
        fprintf(stderr, "no resumption session delivered — would fall back + emit event\n");
        return 1;
    }
    printf("destination : %s:%s\n", host, port);
    printf("group       : %s\n", result.group);
    printf("pqc         : %s\n", result.is_pqc ? "yes (ML-KEM hybrid)" : "no (classical)");
    printf("resumable   : %s\n", SSL_SESSION_is_resumable(result.session) ? "yes" : "no");
    printf("lifetime    : %lu s\n", (unsigned long)SSL_SESSION_get_timeout(result.session));

    unsigned char* der = NULL;
    int der_len = session_to_der(result.session, &der);
    printf("der bytes   : %d\n", der_len);
    if (der_out != NULL && der_len > 0) {
        write_der(der_out, der, der_len);
    }
    free(der);
    SSL_SESSION_free(result.session);
    return 0;
}

static int cmd_serve(int argc, char** argv)
{
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }
    const char* sock = argv[2];
    struct Live_ctx lc = {0};
    int depth = 4;

    const char* dests[64];
    int ndest = 0;
    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "-k") == 0) {
            lc.insecure = 1;
        }
        else if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc) {
            depth = atoi(argv[++i]);
        }
        else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 2;
        }
        else if (ndest < (int)(sizeof(dests) / sizeof(dests[0]))) {
            dests[ndest++] = argv[i];
        }
    }
    if (ndest == 0) {
        usage(argv[0]);
        return 2;
    }

    Pool* pool = pool_new(live_source, &lc, depth);
    if (pool == NULL) {
        fprintf(stderr, "pool_new failed\n");
        return 1;
    }
    for (int i = 0; i < ndest; ++i) {
        int got = pool_maintain(pool, dests[i]);
        printf("prewarm     : %s -> %d/%d\n", dests[i], got, depth);
    }
    printf("serving     : %s\n", sock);
    int rc = uds_serve(sock, pool);
    pool_free(pool);
    return rc;
}

static int cmd_get(int argc, char** argv)
{
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }
    const char* sock = argv[2];
    const char* dest = argv[3];
    const char* der_out = NULL;
    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            der_out = argv[++i];
        }
        else {
            usage(argv[0]);
            return 2;
        }
    }

    unsigned char* der = NULL;
    int der_len = 0;
    int is_pqc = 0;
    char group[64] = {0};
    int status = uds_get(sock, dest, &der, &der_len, &is_pqc, group, sizeof(group));
    if (status < 0) {
        fprintf(stderr, "transport error talking to %s\n", sock);
        return 1;
    }
    if (status == UDS_STATUS_MISS) {
        fprintf(stderr, "miss: no session for %s (would fall back + emit event)\n", dest);
        return 1;
    }
    if (status != UDS_STATUS_OK) {
        fprintf(stderr, "agent error for %s\n", dest);
        return 1;
    }

    printf("destination : %s\n", dest);
    printf("group       : %s\n", group);
    printf("pqc         : %s\n", is_pqc ? "yes (ML-KEM hybrid)" : "no (classical)");
    printf("der bytes   : %d\n", der_len);
    if (der_out != NULL && der_len > 0) {
        write_der(der_out, der, der_len);
    }
    free(der);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "fetch") == 0) {
        return cmd_fetch(argc, argv);
    }
    if (strcmp(argv[1], "serve") == 0) {
        return cmd_serve(argc, argv);
    }
    if (strcmp(argv[1], "get") == 0) {
        return cmd_get(argc, argv);
    }
    usage(argv[0]);
    return 2;
}
