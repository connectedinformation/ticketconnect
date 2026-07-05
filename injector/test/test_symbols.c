// Tier 1/3 — runtime .dynsym resolution, no offset database. Resolve getpid in
// libc, call it to prove the address is right; resolve across a forked target;
// and confirm fail-closed on unknown symbol/library.

#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "symbols.h"

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
    pid_t self = getpid();

    // Resolve getpid in our own libc and call it — a wrong address would not
    // return our pid (or would crash), so a correct return proves resolution.
    unsigned long addr = resolve_symbol(self, "libc.so", "getpid");
    CHECK(addr != 0, "getpid resolves in libc");
    if (addr != 0) {
        pid_t (*fn)(void) = (pid_t (*)(void))addr;
        CHECK(fn() == self, "resolved getpid() actually returns our pid");
    }

    // mmap is what the injector needs for the scratch buffer — must resolve.
    CHECK(resolve_symbol(self, "libc.so", "mmap") != 0, "mmap resolves in libc");

    // Cross-process: resolve in a forked child; post-fork the layout is shared,
    // so the child's getpid address must match ours — exercises /proc/<pid>/ path.
    pid_t child = fork();
    if (child == 0) {
        for (volatile unsigned long i = 0; i < 20000000000UL; ++i) {
        }
        _exit(0);
    }
    unsigned long child_addr = resolve_symbol(child, "libc.so", "getpid");
    CHECK(child_addr == addr, "resolving in another process yields the same address");
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // Fail-closed: unknown symbol and unknown library both return 0.
    CHECK(resolve_symbol(self, "libc.so", "no_such_symbol_xyz") == 0,
          "unknown symbol fails closed (0)");
    CHECK(resolve_symbol(self, "libnope_xyz.so", "getpid") == 0,
          "unknown library fails closed (0)");

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
