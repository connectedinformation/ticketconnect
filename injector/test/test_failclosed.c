// Tier 3 (negatives) — the fail-closed guards (DESIGN §7). The property under
// test is the one that earns the privilege: "worst case is no upgrade, never a
// corrupted process." All unprivileged (own children; yama permissive).
//
//   1. Unresolved symbol set -> inject_session skips before any ptrace action,
//      target untouched and alive.
//   2. Garbage DER -> remote d2i_SSL_SESSION returns NULL -> no SSL_set_session,
//      target left uncorrupted (exits cleanly, no crash signal).
//   3. PTRACE_O_EXITKILL -> a tracer that dies mid-injection kills the target
//      (SIGKILL) rather than leaving it stopped forever.

#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "install.h"
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

static int alive(pid_t pid)
{
    return kill(pid, 0) == 0;
}

static void wait_for_comm(pid_t pid, const char* want)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    for (int i = 0; i < 200000; ++i) {
        FILE* f = fopen(path, "r");
        if (f) {
            char comm[64] = {0};
            if (fgets(comm, sizeof(comm), f)) {
                comm[strcspn(comm, "\n")] = '\0';
                if (strcmp(comm, want) == 0) {
                    fclose(f);
                    return;
                }
            }
            fclose(f);
        }
        sched_yield();
    }
}

// 1. A target with no libssl mapped: inject_session must fail-closed before it
// ever seizes the process.
static void test_unresolved(void)
{
    printf("1. unresolved symbol set (no libssl in target)\n");
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sleep", "sleep", "30", (char*)NULL);
        _exit(127);
    }
    wait_for_comm(pid, "sleep"); // ensure exec completed (libssl-free maps)

    unsigned char dummy[8] = {0};
    int rc = inject_session(pid, 0xdeadbeef, dummy, sizeof(dummy));
    CHECK(rc < 0, "inject_session refuses (returns < 0)");
    CHECK(alive(pid), "target left running (never seized)");

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

// 2. A real libssl victim, garbage DER: d2i rejects it, nothing is installed, and
// the victim is not corrupted.
static void test_garbage_der(void)
{
    printf("2. garbage DER into a real libssl victim (no corruption)\n");
    volatile int* go =
        mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *go = 0;
    int pfd[2];
    if (pipe(pfd) != 0) {
        return;
    }

    pid_t child = fork();
    if (child == 0) {
        close(pfd[0]);
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        SSL* ssl = SSL_new(ctx);
        unsigned long a = (unsigned long)ssl;
        if (write(pfd[1], &a, sizeof(a)) != (ssize_t)sizeof(a)) {
            _exit(11);
        }
        while (!*go) {
        }
        SSL_free(ssl); // if the heap were corrupted this would likely crash
        _exit(0);
    }
    close(pfd[1]);

    unsigned long ssl_ptr = 0;
    if (read(pfd[0], &ssl_ptr, sizeof(ssl_ptr)) != (ssize_t)sizeof(ssl_ptr)) {
        CHECK(0, "received victim SSL pointer");
        return;
    }

    unsigned char garbage[64];
    memset(garbage, 0xAB, sizeof(garbage));
    int rc = inject_session(child, ssl_ptr, garbage, sizeof(garbage));
    CHECK(rc < 0, "inject_session rejects a bad payload (returns < 0)");

    *go = 1;
    int st = 0;
    waitpid(child, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "victim exited cleanly (no corruption/crash)");
    if (WIFSIGNALED(st)) {
        printf("        (victim killed by signal %d)\n", WTERMSIG(st));
    }
}

// 3. PTRACE_O_EXITKILL: a tracer that seizes then dies without detaching must not
// leave the target stopped — the kernel kills it.
static void test_exitkill(void)
{
    printf("3. PTRACE_O_EXITKILL (dead injector never leaves a target stopped)\n");
    pid_t victim = fork();
    if (victim == 0) {
        // Long spin — bounded so a broken EXITKILL turns into a FAIL, not a hang.
        for (volatile unsigned long i = 0; i < 30000000000UL; ++i) {
        }
        _exit(0);
    }

    pid_t injector = fork();
    if (injector == 0) {
        // Seize with O_EXITKILL, then die without detaching.
        if (injector_seize(victim) != 0) {
            _exit(1);
        }
        _exit(0);
    }
    waitpid(injector, NULL, 0);

    int st = 0;
    waitpid(victim, &st, 0);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
          "target SIGKILLed when the tracer died (not left stopped)");
    if (WIFEXITED(st)) {
        printf("        (target exited normally — EXITKILL did not fire)\n");
    }
}

int main(void)
{
    test_unresolved();
    test_garbage_der();
    test_exitkill();
    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
