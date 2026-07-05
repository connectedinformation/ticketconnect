// symbols — resolve an EXPORTED symbol's runtime address in a target process.
//
// Public-API-only injection means every function we call (d2i_SSL_SESSION,
// SSL_set_session, SSL_SESSION_free, mmap, ...) is in the library's .dynsym — the
// dynamic symbol table, which is present even in stripped production builds. So
// resolution is fully runtime: load bias from /proc/<pid>/maps + st_value from
// .dynsym, no pre-computed offset database (contrast the prior tree's SHA256-keyed
// signature DB, which existed to carry private struct offsets we no longer touch).
//
// Container-aware: the library is read through /proc/<pid>/root so we see the
// exact file the target has mapped, in its mount namespace.

#ifndef TICKETCONNECT_INJECTOR_SYMBOLS_H
#define TICKETCONNECT_INJECTOR_SYMBOLS_H

#include <sys/types.h>

// Resolve `sym` in the mapped library whose path contains `lib_substr` (e.g.
// "libssl.so", "libc.so") for process `pid`. Returns the runtime address, or 0 if
// the library or a *defined* symbol of that name is not found (fail-closed).
unsigned long resolve_symbol(pid_t pid, const char* lib_substr, const char* sym);

#endif // TICKETCONNECT_INJECTOR_SYMBOLS_H
