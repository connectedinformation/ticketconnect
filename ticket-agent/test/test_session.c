// Tier 1 (session source) + Tier 2 (resume round-trip) tests — see
// docs/TEST_PLAN.md. Requires a PQC s_server on host:port (run.sh provides one).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "session_source.h"

static int g_checks = 0;
static int g_fails = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (cond) {                                                                                \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else {                                                                                     \
            printf("  FAIL : %s\n", (msg));                                                        \
            ++g_fails;                                                                             \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv)
{
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char* port = (argc > 2) ? argv[2] : "14433";
    const int insecure = 1; // self-signed test server

    printf("Tier 1 — session source (%s:%s)\n", host, port);
    struct Fetch_result r;
    int frc = session_fetch(host, port, insecure, &r);
    CHECK(frc == 0, "session_fetch succeeds");
    if (frc != 0) {
        printf("cannot proceed without a session\n");
        return 1;
    }
    CHECK(r.session != NULL, "a session was captured");
    CHECK(SSL_SESSION_is_resumable(r.session), "captured session is resumable");
    CHECK(strcmp(r.group, "X25519MLKEM768") == 0, "negotiated group is X25519MLKEM768");
    CHECK(r.is_pqc, "provenance flag reports PQC");

    // DER round-trip: i2d then d2i must yield a session again.
    unsigned char* der = NULL;
    int der_len = session_to_der(r.session, &der);
    CHECK(der_len > 0, "session serializes to DER");
    const unsigned char* p = der;
    SSL_SESSION* back = d2i_SSL_SESSION(NULL, &p, (long)der_len);
    CHECK(back != NULL, "DER round-trips back to an SSL_SESSION");
    CHECK(back != NULL && SSL_SESSION_is_resumable(back), "round-tripped session is resumable");
    if (back != NULL) {
        SSL_SESSION_free(back);
    }

    printf("Tier 2 — resume round-trip (payload proof)\n");
    int reused = 0;
    char group[64] = {0};
    int prc = session_probe_resume(host, port, insecure, der, (size_t)der_len, &reused, group,
                                   sizeof(group));
    CHECK(prc == 0, "resume handshake succeeds");
    CHECK(reused == 1, "connection resumed via PSK (SSL_session_reused)");

    free(der);
    SSL_SESSION_free(r.session);

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
