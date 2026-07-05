// Tier 1 — UDS protocol parser, hermetic. Focuses on malformed-input rejection
// (the test plan's negative-path requirement) plus one well-formed accept.

#include <stdio.h>
#include <string.h>

#include "uds.h"

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

int main(void)
{
    uint8_t op = 0;
    char dest[UDS_DEST_MAX + 1];

    // Well-formed GET for "a:1".
    unsigned char ok[] = {UDS_MAGIC, UDS_VERSION, UDS_OP_GET, 3, 'a', ':', '1'};
    CHECK(uds_parse_request(ok, sizeof(ok), &op, dest, sizeof(dest)) == 0 && op == UDS_OP_GET &&
              strcmp(dest, "a:1") == 0,
          "well-formed GET parses");

    // Too short for even a header.
    unsigned char shortbuf[] = {UDS_MAGIC, UDS_VERSION};
    CHECK(uds_parse_request(shortbuf, sizeof(shortbuf), &op, dest, sizeof(dest)) < 0,
          "truncated header is rejected");

    // Bad magic.
    unsigned char badmagic[] = {0x00, UDS_VERSION, UDS_OP_GET, 1, 'x'};
    CHECK(uds_parse_request(badmagic, sizeof(badmagic), &op, dest, sizeof(dest)) < 0,
          "bad magic is rejected");

    // Bad version.
    unsigned char badver[] = {UDS_MAGIC, 0xFF, UDS_OP_GET, 1, 'x'};
    CHECK(uds_parse_request(badver, sizeof(badver), &op, dest, sizeof(dest)) < 0,
          "bad version is rejected");

    // dest_len says 5 but only 1 byte follows.
    unsigned char mismatch[] = {UDS_MAGIC, UDS_VERSION, UDS_OP_GET, 5, 'x'};
    CHECK(uds_parse_request(mismatch, sizeof(mismatch), &op, dest, sizeof(dest)) < 0,
          "dest_len/length mismatch is rejected");

    // Zero-length destination.
    unsigned char zerodest[] = {UDS_MAGIC, UDS_VERSION, UDS_OP_GET, 0};
    CHECK(uds_parse_request(zerodest, sizeof(zerodest), &op, dest, sizeof(dest)) < 0,
          "zero-length dest is rejected");

    // Unknown op.
    unsigned char badop[] = {UDS_MAGIC, UDS_VERSION, 0x99, 1, 'x'};
    CHECK(uds_parse_request(badop, sizeof(badop), &op, dest, sizeof(dest)) < 0,
          "unknown op is rejected");

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
