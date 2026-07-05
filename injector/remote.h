// remote — the ptrace remote-call primitive (x86-64).
//
// The safety-critical core of the injector (DESIGN.md §7): make a stopped target
// thread execute a *public, exported* function with our arguments, then read the
// return value — without ever writing a private struct field. Everything the
// injector does (remote mmap, d2i_SSL_SESSION, SSL_set_session) is built on this
// one call. Proving it in isolation (test/test_remote.c) de-risks the rest.

#ifndef TICKETCONNECT_INJECTOR_REMOTE_H
#define TICKETCONNECT_INJECTOR_REMOTE_H

#include <sys/types.h>

// PTRACE_SEIZE the thread (PTRACE_O_EXITKILL always — a dead injector never
// leaves a target stopped) and PTRACE_INTERRUPT it into a ptrace-stop. Returns 0
// on success. The target must be a thread we are allowed to trace.
int injector_seize(pid_t pid);

// Detach, letting the target run normally again.
int injector_detach(pid_t pid);

// Call func(a0..a5) in the seized (stopped) target and return its return value
// (the AMD64 %rax). *ok is set to 1 on success, 0 on failure. The target's
// registers and the one code byte used as a return trap are restored afterward,
// so the target resumes exactly where it was interrupted.
unsigned long remote_call(pid_t pid, unsigned long func, unsigned long a0, unsigned long a1,
                          unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5,
                          int* ok);

#endif // TICKETCONNECT_INJECTOR_REMOTE_H
