// pool — per-destination session inventory (DESIGN.md §5.1).
//
// The pool sits between sourcing and delivery: it holds depth per destination so
// injection is an instant lookup rather than an on-demand handshake, and it
// evicts sessions before expiry (TLS 1.3 tickets are effectively single-use, so
// pool_get consumes one). The source is injected as a function pointer, so the
// pool logic is unit-testable with no network (see test/test_pool.c).

#ifndef TICKETCONNECT_POOL_H
#define TICKETCONNECT_POOL_H

#include <stddef.h>

// Produce one session for `dest`. On success returns 0 and sets: *der to a
// malloc'd DER buffer the pool takes ownership of, *der_len its length, *is_pqc
// the provenance flag, group the negotiated group name (into a group_cap buffer),
// *lifetime_s the session lifetime in seconds. Returns non-zero on failure.
typedef int (*Pool_source_fn)(void* ctx, const char* dest, unsigned char** der, int* der_len,
                              int* is_pqc, char* group, size_t group_cap, long* lifetime_s);

typedef struct Pool Pool;

Pool* pool_new(Pool_source_fn src, void* src_ctx, int target_depth);
void pool_free(Pool* p);

// Top `dest` up to target depth (evicting expired entries first). Returns the
// available depth afterward. A source failure stops early — a partial fill is
// not an error (cold start / upstream trouble is handled by the miss path).
int pool_maintain(Pool* p, const char* dest);

// Available (non-expired) depth for `dest`.
int pool_depth(Pool* p, const char* dest);

// Pop one non-expired session for `dest` (single-use). Returns 1 on a hit with
// ownership of *der transferred to the caller (free it), 0 on a miss. A miss is
// the cold-start / downgrade signal — never silent at the call site.
int pool_get(Pool* p, const char* dest, unsigned char** der, int* der_len, int* is_pqc, char* group,
             size_t group_cap);

#endif // TICKETCONNECT_POOL_H
