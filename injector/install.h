// install — the session install (DESIGN.md §5.2, §7), composed from the two
// proven primitives: resolve exported symbols (symbols.h) and remote-call them
// (remote.h). No private struct field is ever written — only public OpenSSL APIs
// invoked by address, on memory we allocated.

#ifndef TICKETCONNECT_INJECTOR_INSTALL_H
#define TICKETCONNECT_INJECTOR_INSTALL_H

#include <stddef.h>
#include <sys/types.h>

// Install a serialized resumption session (DER) into the live SSL object at
// `ssl_ptr` in process `pid`, so the target's next SSL_connect resumes on it.
//
// Sequence: resolve mmap/d2i_SSL_SESSION/SSL_set_session/SSL_SESSION_free; verify
// the whole set before acting (fail-closed); seize; remote-mmap a scratch buffer;
// process_vm_writev the DER in; remote d2i_SSL_SESSION -> SSL_set_session ->
// SSL_SESSION_free; remote-munmap; detach.
//
// Returns 0 on success (SSL_set_session returned 1), negative otherwise. On any
// failure the target is left running and uncorrupted — worst case is "no upgrade".
int inject_session(pid_t pid, unsigned long ssl_ptr, const unsigned char* der, size_t der_len);

#endif // TICKETCONNECT_INJECTOR_INSTALL_H
