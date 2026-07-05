// install — see install.h. x86-64 / Linux.

#define _GNU_SOURCE

#include "install.h"

#include "remote.h"
#include "symbols.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>

// Write into the (stopped, seized) target's memory — always a buffer we just
// allocated, so no knowledge of the target's layout is used.
static int write_mem(pid_t pid, unsigned long addr, const void* buf, size_t n)
{
    struct iovec local = {.iov_base = (void*)buf, .iov_len = n};
    struct iovec remote = {.iov_base = (void*)addr, .iov_len = n};
    ssize_t w = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (w == (ssize_t)n) ? 0 : -1;
}

static unsigned long round_up(unsigned long v, unsigned long a)
{
    return (v + a - 1) & ~(a - 1);
}

int inject_session(pid_t pid, unsigned long ssl_ptr, const unsigned char* der, size_t der_len)
{
    // Resolve the full public-API set up front and verify it before touching the
    // target — fail-closed (DESIGN §7): a missing symbol means "no upgrade".
    unsigned long fn_mmap = resolve_symbol(pid, "libc.so", "mmap");
    unsigned long fn_munmap = resolve_symbol(pid, "libc.so", "munmap");
    unsigned long fn_d2i = resolve_symbol(pid, "libssl.so", "d2i_SSL_SESSION");
    unsigned long fn_set = resolve_symbol(pid, "libssl.so", "SSL_set_session");
    unsigned long fn_free = resolve_symbol(pid, "libssl.so", "SSL_SESSION_free");
    if (!fn_mmap || !fn_munmap || !fn_d2i || !fn_set || !fn_free) {
        fprintf(stderr, "inject: unresolved symbol set — skipping (fail-closed)\n");
        return -1;
    }

    if (injector_seize(pid) != 0) {
        return -1;
    }

    int rc = -1;
    int ok = 0;
    unsigned long page = round_up(der_len + 16, 4096);

    // mmap(NULL, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    unsigned long scratch = remote_call(pid, fn_mmap, 0, page, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0, &ok);
    if (!ok || scratch == 0 || scratch == (unsigned long)-1) {
        fprintf(stderr, "inject: remote mmap failed\n");
        goto detach;
    }

    // DER at scratch; a pointer-to-DER just past it for d2i's in/out argument.
    unsigned long ptrloc = scratch + round_up(der_len, 8);
    if (write_mem(pid, scratch, der, der_len) != 0 ||
        write_mem(pid, ptrloc, &scratch, sizeof(scratch)) != 0) {
        fprintf(stderr, "inject: process_vm_writev failed\n");
        goto unmap;
    }

    // d2i_SSL_SESSION(NULL, &ptr, der_len) -> SSL_SESSION* in the target heap.
    unsigned long sess = remote_call(pid, fn_d2i, 0, ptrloc, der_len, 0, 0, 0, &ok);
    if (!ok || sess == 0) {
        fprintf(stderr, "inject: remote d2i_SSL_SESSION failed\n");
        goto unmap;
    }

    // SSL_set_session(ssl, sess); then drop our reference regardless.
    unsigned long set_ret = remote_call(pid, fn_set, ssl_ptr, sess, 0, 0, 0, 0, &ok);
    int set_ok = ok;
    int free_ok = 0;
    remote_call(pid, fn_free, sess, 0, 0, 0, 0, 0, &free_ok);
    if (!set_ok || (int)set_ret != 1) {
        fprintf(stderr, "inject: SSL_set_session returned %d\n", (int)set_ret);
        goto unmap;
    }
    rc = 0;

unmap:
    remote_call(pid, fn_munmap, scratch, page, 0, 0, 0, 0, &ok);
detach:
    injector_detach(pid);
    return rc;
}
