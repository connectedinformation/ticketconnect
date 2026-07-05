// remote — see remote.h. x86-64 / Linux only.

#define _GNU_SOURCE

#include "remote.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

// Older headers may not expose the SEIZE-family constants.
#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif

int injector_seize(pid_t pid)
{
    if (ptrace(PTRACE_SEIZE, pid, 0, (void*)PTRACE_O_EXITKILL) < 0) {
        perror("PTRACE_SEIZE");
        return -1;
    }
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0) {
        perror("PTRACE_INTERRUPT");
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid(seize)");
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target did not stop after interrupt\n");
        return -1;
    }
    return 0;
}

int injector_detach(pid_t pid)
{
    return ptrace(PTRACE_DETACH, pid, 0, 0) < 0 ? -1 : 0;
}

static int poke_byte(pid_t pid, unsigned long addr, unsigned char value, unsigned char* saved_word)
{
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
    if (word == -1 && errno != 0) {
        return -1;
    }
    if (saved_word != NULL) {
        memcpy(saved_word, &word, sizeof(word));
    }
    unsigned long patched = ((unsigned long)word & ~0xFFUL) | value;
    return ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)patched) < 0 ? -1 : 0;
}

unsigned long remote_call(pid_t pid, unsigned long func, unsigned long a0, unsigned long a1,
                          unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5,
                          int* ok)
{
    *ok = 0;

    struct user_regs_struct saved;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved) < 0) {
        perror("GETREGS");
        return 0;
    }

    // Use the interrupted rip as the return trap: overwrite its first byte with
    // int3, point the call's return address there. The target never executes
    // this instruction as its own code — rip is set to func for the call — and
    // both the byte and the registers are restored before it resumes.
    unsigned long trap = saved.rip;
    unsigned char orig_word[sizeof(long)];
    if (poke_byte(pid, trap, 0xCC, orig_word) < 0) {
        perror("plant trap");
        return 0;
    }

    struct user_regs_struct regs = saved;
    regs.rip = func;
    regs.rdi = a0;
    regs.rsi = a1;
    regs.rdx = a2;
    regs.rcx = a3;
    regs.r8 = a4;
    regs.r9 = a5;

    // AMD64: rsp must be 16-aligned at the call site; after the pushed return
    // address, the callee sees rsp % 16 == 8. Clear the red zone, align, push.
    unsigned long sp = saved.rsp;
    sp -= 256;
    sp &= ~0xFUL;
    sp -= 8;
    if (ptrace(PTRACE_POKEDATA, pid, (void*)sp, (void*)trap) < 0) {
        perror("push return addr");
        goto restore;
    }
    regs.rsp = sp;

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
        perror("SETREGS(call)");
        goto restore;
    }

    int spurious = 0;
    for (;;) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
            perror("CONT");
            goto restore;
        }
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid(call)");
            goto restore;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            fprintf(stderr, "target died during remote call\n");
            return 0;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            break; // hit our return trap — the call has returned
        }
        // A group-stop (e.g. the pending SIGSTOP the eBPF uprobe used to freeze
        // the thread) or another signal-stop: re-continue without delivering it
        // and keep waiting for our return trap. Bounded so a genuine fault can't
        // spin forever.
        if (++spurious > 16) {
            fprintf(stderr, "remote call stuck on signal %d\n", WSTOPSIG(status));
            goto restore;
        }
    }

    struct user_regs_struct after;
    if (ptrace(PTRACE_GETREGS, pid, 0, &after) < 0) {
        perror("GETREGS(result)");
        goto restore;
    }

    // Restore the trap byte and the original register state.
    ptrace(PTRACE_POKETEXT, pid, (void*)trap, (void*)*(long*)orig_word);
    ptrace(PTRACE_SETREGS, pid, 0, &saved);
    *ok = 1;
    return after.rax;

restore:
    ptrace(PTRACE_POKETEXT, pid, (void*)trap, (void*)*(long*)orig_word);
    ptrace(PTRACE_SETREGS, pid, 0, &saved);
    return 0;
}
