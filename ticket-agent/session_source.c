// session_source — see session_source.h.

#define _POSIX_C_SOURCE 200112L

#include "session_source.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

// The hybrid group the agent prefers (draft-ietf-tls-ecdhe-mlkem; ML-KEM = FIPS
// 203). Classical fallbacks follow so a handshake still completes against a
// non-PQC upstream — the negotiated group we report says what we actually got.
static const char* const k_group_pref = "X25519MLKEM768:X25519:P-256";

static int on_new_session(SSL* ssl, SSL_SESSION* sess)
{
    struct Fetch_result* result = SSL_get_app_data(ssl);
    if (result != NULL && result->session == NULL) {
        SSL_SESSION_up_ref(sess); // keep our own reference
        result->session = sess;
    }
    return 0; // OpenSSL retains its own reference independently
}

static int connect_tcp(const char* host, const char* port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* list = NULL;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* ai = list; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);

    if (fd < 0) {
        fprintf(stderr, "connect(%s:%s): failed\n", host, port);
    }
    return fd;
}

// Drive post-handshake reads so the NewSessionTicket records are processed and
// on_new_session() fires. A short recv timeout lets a blocking read return once
// the server has nothing more to send (it will not send application data
// unprompted). RFC 8446 §4.6.1: tickets arrive after the handshake completes.
static void pump_for_ticket(SSL* ssl, int fd, struct Fetch_result* result)
{
    struct timeval tv = {.tv_sec = 1, .tv_usec = 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int attempt = 0; attempt < 4 && result->session == NULL; ++attempt) {
        unsigned char buf[512];
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            continue; // unexpected app data; keep pumping for the ticket
        }
        int err = SSL_get_error(ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            break; // clean EOF or fatal error — nothing more coming
        }
    }
}

static SSL_CTX* make_ctx(int insecure, int with_new_cb)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_set1_groups_list(ctx, k_group_pref) != 1) {
        fprintf(stderr, "set groups list failed\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (with_new_cb) {
        // Capture tickets as they arrive; the callback is our session source.
        SSL_CTX_set_session_cache_mode(ctx,
                                       SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx, on_new_session);
    }

    if (insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    }
    return ctx;
}

int session_fetch(const char* host, const char* port, int insecure, struct Fetch_result* out)
{
    memset(out, 0, sizeof(*out));

    SSL_CTX* ctx = make_ctx(insecure, 1);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int fd = connect_tcp(host, port);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_app_data(ssl, out);
    SSL_set_tlsext_host_name(ssl, host); // SNI
    if (!insecure) {
        SSL_set1_host(ssl, host);
    }

    int rc = 1;
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "handshake failed:\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    const char* group = SSL_get0_group_name(ssl);
    snprintf(out->group, sizeof(out->group), "%s", group != NULL ? group : "?");
    out->is_pqc = (group != NULL && strstr(group, "MLKEM") != NULL);

    pump_for_ticket(ssl, fd, out);
    rc = (out->session != NULL) ? 0 : 1; // no session is a failure, never silent

out:
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return rc;
}

int session_to_der(SSL_SESSION* sess, unsigned char** der)
{
    int len = i2d_SSL_SESSION(sess, NULL);
    if (len <= 0) {
        return len;
    }
    unsigned char* buf = malloc((size_t)len);
    if (buf == NULL) {
        return -1;
    }
    unsigned char* p = buf;
    i2d_SSL_SESSION(sess, &p);
    *der = buf;
    return len;
}

int session_probe_resume(const char* host, const char* port, int insecure, const unsigned char* der,
                         size_t der_len, int* reused, char* group_out, size_t group_len)
{
    *reused = 0;

    SSL_CTX* ctx = make_ctx(insecure, 0);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int fd = connect_tcp(host, port);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (!insecure) {
        SSL_set1_host(ssl, host);
    }

    // The injector payload, modeled in userspace: materialize the session from
    // DER via the public API and install it, exactly as the remote calls will.
    const unsigned char* p = der;
    SSL_SESSION* sess = d2i_SSL_SESSION(NULL, &p, (long)der_len);
    if (sess == NULL) {
        fprintf(stderr, "d2i_SSL_SESSION failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_set_session(ssl, sess); // takes its own reference
    SSL_SESSION_free(sess);

    int rc = 1;
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "resume handshake failed:\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    *reused = SSL_session_reused(ssl);
    if (group_out != NULL && group_len > 0) {
        const char* group = SSL_get0_group_name(ssl);
        snprintf(group_out, group_len, "%s", group != NULL ? group : "?");
    }
    rc = 0;

out:
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return rc;
}
