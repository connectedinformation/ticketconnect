// uds — node-local Unix-socket protocol between agent and injector.
//
// The agent (authority) serves serialized sessions + provenance; the injector is
// the client. Framing is explicit and length-bounded (no library, no ambiguity):
//
//   request : 'T' | version | op | dest_len | dest[dest_len]
//   response: 'T' | version | status | is_pqc | group_len | der_len(u32 BE)
//             | group[group_len] | der[der_len]
//
// A miss (empty pool) is a first-class status, not a dropped connection — the
// caller must see it to honor "no silent downgrade" (DESIGN.md §10).

#ifndef TICKETCONNECT_UDS_H
#define TICKETCONNECT_UDS_H

#include <stddef.h>
#include <stdint.h>

#include "pool.h"

enum {
    UDS_MAGIC = 0x54, // 'T'
    UDS_VERSION = 1,
    UDS_OP_GET = 1,
    UDS_STATUS_OK = 0,
    UDS_STATUS_MISS = 1,
    UDS_STATUS_ERROR = 2,
    UDS_REQ_HDR = 4,
    UDS_RESP_HDR = 9,
    UDS_DEST_MAX = 255
};

// Validate and parse a complete request frame. Returns 0 and sets *op and dest
// (NUL-terminated, into a dest_cap buffer) on success; negative on any malformed
// input (bad magic/version, unknown op, dest_len mismatch, oversize). Pure — the
// unit tests exercise it directly with crafted buffers.
int uds_parse_request(const unsigned char* buf, size_t len, uint8_t* op, char* dest,
                      size_t dest_cap);

// Serve pool sessions over the Unix socket at `path` until the process is killed.
// Blocking, one client at a time. Returns non-zero on a fatal setup error.
int uds_serve(const char* path, Pool* pool);

// Client: request a session for `dest` from the agent at `path`. Returns the
// UDS_STATUS_* code (>=0), or negative on a transport error. On OK, *der is a
// malloc'd buffer (caller frees), with *der_len/*is_pqc/group filled.
int uds_get(const char* path, const char* dest, unsigned char** der, int* der_len, int* is_pqc,
            char* group, size_t group_cap);

#endif // TICKETCONNECT_UDS_H
