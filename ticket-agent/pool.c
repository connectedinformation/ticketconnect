// pool — see pool.h. Single-threaded: the agent serves one request at a time in
// v1; add locking if the server is later threaded.

#include "pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { DEST_MAX = 255, GROUP_MAX = 64 };

struct Pool_entry {
    unsigned char* der;
    int der_len;
    int is_pqc;
    char group[GROUP_MAX];
    time_t expires_at;
};

struct Pool_dest {
    char dest[DEST_MAX + 1];
    struct Pool_entry* entries; // capacity == target_depth
    int count;
    struct Pool_dest* next;
};

struct Pool {
    Pool_source_fn src;
    void* src_ctx;
    int target_depth;
    struct Pool_dest* dests;
};

Pool* pool_new(Pool_source_fn src, void* src_ctx, int target_depth)
{
    if (target_depth < 1) {
        target_depth = 1;
    }
    Pool* p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->src = src;
    p->src_ctx = src_ctx;
    p->target_depth = target_depth;
    return p;
}

static void entry_clear(struct Pool_entry* e)
{
    free(e->der);
    memset(e, 0, sizeof(*e));
}

void pool_free(Pool* p)
{
    if (p == NULL) {
        return;
    }
    struct Pool_dest* d = p->dests;
    while (d != NULL) {
        struct Pool_dest* next = d->next;
        for (int i = 0; i < d->count; ++i) {
            entry_clear(&d->entries[i]);
        }
        free(d->entries);
        free(d);
        d = next;
    }
    free(p);
}

static struct Pool_dest* dest_find(Pool* p, const char* dest)
{
    for (struct Pool_dest* d = p->dests; d != NULL; d = d->next) {
        if (strcmp(d->dest, dest) == 0) {
            return d;
        }
    }
    return NULL;
}

static struct Pool_dest* dest_intern(Pool* p, const char* dest)
{
    if (strlen(dest) > DEST_MAX) {
        return NULL;
    }
    struct Pool_dest* d = dest_find(p, dest);
    if (d != NULL) {
        return d;
    }
    d = calloc(1, sizeof(*d));
    if (d == NULL) {
        return NULL;
    }
    d->entries = calloc((size_t)p->target_depth, sizeof(*d->entries));
    if (d->entries == NULL) {
        free(d);
        return NULL;
    }
    snprintf(d->dest, sizeof(d->dest), "%s", dest);
    d->next = p->dests;
    p->dests = d;
    return d;
}

// Drop expired entries, compacting the array so [0, count) stays live.
static void evict_expired(struct Pool_dest* d)
{
    time_t now = time(NULL);
    int w = 0;
    for (int r = 0; r < d->count; ++r) {
        if (d->entries[r].expires_at > now) {
            if (w != r) {
                d->entries[w] = d->entries[r];
            }
            ++w;
        }
        else {
            entry_clear(&d->entries[r]);
        }
    }
    d->count = w;
}

int pool_maintain(Pool* p, const char* dest)
{
    struct Pool_dest* d = dest_intern(p, dest);
    if (d == NULL) {
        return 0;
    }
    evict_expired(d);

    while (d->count < p->target_depth) {
        unsigned char* der = NULL;
        int der_len = 0;
        int is_pqc = 0;
        char group[GROUP_MAX] = {0};
        long lifetime = 0;
        if (p->src(p->src_ctx, dest, &der, &der_len, &is_pqc, group, sizeof(group), &lifetime) !=
            0) {
            break; // partial fill is not an error — the miss path covers it
        }
        struct Pool_entry* e = &d->entries[d->count];
        e->der = der;
        e->der_len = der_len;
        e->is_pqc = is_pqc;
        snprintf(e->group, sizeof(e->group), "%s", group);
        e->expires_at = time(NULL) + (lifetime > 0 ? lifetime : 0);
        ++d->count;
    }
    return d->count;
}

int pool_depth(Pool* p, const char* dest)
{
    struct Pool_dest* d = dest_find(p, dest);
    if (d == NULL) {
        return 0;
    }
    evict_expired(d);
    return d->count;
}

int pool_get(Pool* p, const char* dest, unsigned char** der, int* der_len, int* is_pqc, char* group,
             size_t group_cap)
{
    struct Pool_dest* d = dest_find(p, dest);
    if (d == NULL) {
        return 0;
    }
    evict_expired(d);
    if (d->count == 0) {
        return 0; // miss — cold start or upstream failure
    }

    struct Pool_entry* e = &d->entries[--d->count]; // LIFO pop (single-use)
    *der = e->der;                                  // transfer ownership
    *der_len = e->der_len;
    *is_pqc = e->is_pqc;
    if (group != NULL && group_cap > 0) {
        snprintf(group, group_cap, "%s", e->group);
    }
    e->der = NULL;
    memset(e, 0, sizeof(*e));
    return 1;
}
