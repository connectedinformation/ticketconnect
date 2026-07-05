// Tier 1 — pool logic, hermetic (no network; a fake source returns canned DER).
// Covers depth/maintain, single-use get, cold-start miss, expiry eviction.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pool.h"

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

struct Fake {
    int calls;     // how many times the source was invoked
    long lifetime; // lifetime handed to each produced session
    int fail;      // if set, the source always fails (simulates cold upstream)
};

static int fake_source(void* ctx, const char* dest, unsigned char** der, int* der_len, int* is_pqc,
                       char* group, size_t group_cap, long* lifetime_s)
{
    (void)dest;
    struct Fake* f = ctx;
    ++f->calls;
    if (f->fail) {
        return 1;
    }
    unsigned char* buf = malloc(8);
    memcpy(buf, "SESSION0", 8);
    *der = buf;
    *der_len = 8;
    *is_pqc = 1;
    snprintf(group, group_cap, "X25519MLKEM768");
    *lifetime_s = f->lifetime;
    return 0;
}

int main(void)
{
    const char* dest = "example.com:443";

    // maintain fills to target depth; get is single-use.
    struct Fake f = {.lifetime = 3600};
    Pool* p = pool_new(fake_source, &f, 3);
    CHECK(pool_depth(p, dest) == 0, "unknown destination starts empty");

    int filled = pool_maintain(p, dest);
    CHECK(filled == 3, "maintain fills to target depth (3)");
    CHECK(f.calls == 3, "source called exactly target-depth times");

    unsigned char* der = NULL;
    int der_len = 0;
    int is_pqc = 0;
    char group[64] = {0};
    int hit = pool_get(p, dest, &der, &der_len, &is_pqc, group, sizeof(group));
    CHECK(hit == 1, "get returns a hit");
    CHECK(der_len == 8 && der != NULL && memcmp(der, "SESSION0", 8) == 0, "hit carries the DER");
    CHECK(is_pqc == 1 && strcmp(group, "X25519MLKEM768") == 0, "hit carries provenance");
    CHECK(pool_depth(p, dest) == 2, "get consumed one (single-use)");
    free(der);

    // drain to a cold-start miss.
    for (int i = 0; i < 2; ++i) {
        pool_get(p, dest, &der, &der_len, &is_pqc, group, sizeof(group));
        free(der);
    }
    der = NULL;
    CHECK(pool_get(p, dest, &der, &der_len, &is_pqc, group, sizeof(group)) == 0,
          "empty pool returns a miss (cold start)");
    pool_free(p);

    // expiry: lifetime 0 => already expired => evicted, never served.
    struct Fake fe = {.lifetime = 0};
    Pool* pe = pool_new(fake_source, &fe, 3);
    pool_maintain(pe, dest);
    CHECK(pool_depth(pe, dest) == 0, "expired sessions are evicted, not counted");
    der = NULL;
    CHECK(pool_get(pe, dest, &der, &der_len, &is_pqc, group, sizeof(group)) == 0,
          "expired sessions are never served (miss)");
    pool_free(pe);

    // source failure: partial fill is tolerated, not a crash.
    struct Fake ff = {.fail = 1};
    Pool* pf = pool_new(fake_source, &ff, 3);
    CHECK(pool_maintain(pf, dest) == 0, "source failure yields empty pool, no crash");
    pool_free(pf);

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
