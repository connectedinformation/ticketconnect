// Tier 3 (isolated) — prove the ptrace remote-call primitive against a trivial,
// deterministic target: call getpid() inside a spawned child and check it returns
// the child's pid. No symbol resolution needed — after fork the child shares the
// parent's address space layout, so &getpid is valid in both.
//
// Unprivileged: tracing one's own child is always permitted (yama descendant
// rule), so this runs in ordinary CI on Linux/x86-64.

#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "remote.h"

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
    unsigned long fn_getpid = (unsigned long)&getpid;

    pid_t child = fork();
    if (child == 0) {
        // Victim: spin in userspace (no syscalls in the hot loop, so an interrupt
        // lands on plain code) for a bounded time, then exit if left alone.
        volatile unsigned long x = 0;
        for (unsigned long i = 0; i < 20000000000UL; ++i) {
            x += i;
        }
        _exit((int)x);
    }
    if (child < 0) {
        perror("fork");
        return 1;
    }

    printf("Tier 3 — ptrace remote-call primitive (victim pid %d)\n", child);

    int ok = 0;
    CHECK(injector_seize(child) == 0, "seize + interrupt the victim");

    unsigned long ret = remote_call(child, fn_getpid, 0, 0, 0, 0, 0, 0, &ok);
    CHECK(ok == 1, "remote_call completed");
    CHECK((pid_t)ret == child, "remote getpid() returned the victim's pid");

    // A second call proves the target was restored intact and is reusable.
    ok = 0;
    unsigned long ret2 = remote_call(child, fn_getpid, 0, 0, 0, 0, 0, 0, &ok);
    CHECK(ok == 1 && (pid_t)ret2 == child, "a second remote call still works (state restored)");

    injector_detach(child);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
