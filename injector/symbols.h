// symbols — resolve an EXPORTED symbol's runtime address in a target process.
//
// Public-API-only injection means every function we call (d2i_SSL_SESSION,
// SSL_set_session, SSL_SESSION_free, mmap, ...) is in the library's .dynsym — the
// dynamic symbol table, which is present even in stripped production builds. So
// resolution is fully runtime: load bias from /proc/<pid>/maps + st_value from
// .dynsym, with no pre-computed offset database — that only exists for
// offset-based injection, keyed by binary hash to carry private struct offsets,
// which public-API-only injection never touches.
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
