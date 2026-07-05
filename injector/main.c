// injector — the privileged daemon (DESIGN §5.2). Attaches the eBPF SSL_connect
// uprobe (freeze armed), and for each detected connection pulls a session for the
// configured destination from the agent's UDS, installs it over ptrace, and
// releases the frozen thread. A miss falls back to normal TLS and is logged — no
// silent downgrade.
//
//   injector --agent <sock> --dest <host:port> [--pid <N> | --scan] [--dry-run]
//            [--exclude-comm <name>]
//
// --pid targets one process (testing). --scan is node-wide (DaemonSet): discover
// every process with libssl mapped and attach one uprobe per distinct libssl file,
// excluding the agent by comm (probing its own fetch handshakes would deadlock).
// --dry-run lists what --scan would attach, without loading BPF or freezing — safe
// to run anywhere. v1 is single-destination; SNI-based lookup is a later refinement.

#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "event.h"
#include "install.h"
#include "ssl_connect.skel.h"
#include "uds.h"

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

struct daemon_ctx {
    const char* agent_sock;
    const char* dest;
};

// Distinct libssl files we have attached to. Dedup by a container-stable identity:
// overlay mounts present the same underlying libssl with different st_dev, so
// inode dedup would miss cross-container duplicates and attach redundant uprobes
// (a benign but wasteful double-inject). name_to_handle_at() identifies the real
// underlying file across overlay mounts; we fall back to dev:ino if unsupported.
struct attached {
    char key[300];
    struct bpf_link* link;
};
static struct attached g_att[512];
static int g_natt = 0;

static int seen(const char* key)
{
    for (int i = 0; i < g_natt; ++i) {
        if (strcmp(g_att[i].key, key) == 0) {
            return 1;
        }
    }
    return 0;
}

static void file_key(const char* path, const struct stat* st, char* out, size_t cap)
{
    struct {
        struct file_handle fh;
        unsigned char pad[128];
    } h;
    h.fh.handle_bytes = sizeof(h.pad);
    int mount_id = 0;
    if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) == 0) {
        // h.pad backs the flexible f_handle[]; read through it to avoid a
        // zero-length-array bounds warning.
        int n = snprintf(out, cap, "h%d:", h.fh.handle_type);
        for (unsigned i = 0; i < h.fh.handle_bytes && i < sizeof(h.pad) && n < (int)cap - 3; ++i) {
            n += snprintf(out + n, cap - (size_t)n, "%02x", h.pad[i]);
        }
        return;
    }
    snprintf(out, cap, "i%lx:%lx", (unsigned long)st->st_dev, (unsigned long)st->st_ino);
}

static int find_libssl_for_pid(pid_t pid, char* out, size_t cap)
{
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE* f = fopen(maps, "r");
    if (!f) {
        return -1;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char path[512] = {0};
        if (sscanf(line, "%*s %*s %*s %*s %*s %511[^\n]", path) == 1 && strstr(path, "libssl.so")) {
            snprintf(out, cap, "%s", path);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static void read_comm(pid_t pid, char* out, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    out[0] = '\0';
    FILE* f = fopen(path, "r");
    if (f) {
        if (fgets(out, (int)cap, f)) {
            out[strcspn(out, "\n")] = '\0';
        }
        fclose(f);
    }
}

// Scan /proc for processes with libssl mapped; for each distinct libssl file,
// either attach a node-wide uprobe (real) or just report it (dry). Returns the
// number of newly discovered libssl files.
static int scan(struct bpf_program* prog, pid_t self, int dry)
{
    DIR* d = opendir("/proc");
    if (!d) {
        return -1;
    }
    int fresh = 0;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        char* end = NULL;
        long pid = strtol(de->d_name, &end, 10);
        if (*end != '\0' || pid == self) {
            continue;
        }

        char path[512];
        if (find_libssl_for_pid((pid_t)pid, path, sizeof(path)) != 0) {
            continue;
        }
        char rooted[600];
        snprintf(rooted, sizeof(rooted), "/proc/%ld/root%s", pid, path);
        struct stat st;
        const char* use = rooted;
        if (stat(rooted, &st) != 0) {
            if (stat(path, &st) != 0) {
                continue;
            }
            use = path;
        }
        char key[300];
        file_key(use, &st, key, sizeof(key));
        if (seen(key)) {
            continue;
        }

        char comm[64];
        read_comm((pid_t)pid, comm, sizeof(comm));
        if (dry) {
            printf("would attach: %s (first seen via pid %ld comm=%s)\n", use, pid, comm);
            snprintf(g_att[g_natt].key, sizeof(g_att[g_natt].key), "%s", key);
            g_att[g_natt].link = NULL;
            ++g_natt;
        }
        else {
            LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "SSL_connect");
            struct bpf_link* link = bpf_program__attach_uprobe_opts(prog, -1, use, 0, &uo);
            if (link) {
                snprintf(g_att[g_natt].key, sizeof(g_att[g_natt].key), "%s", key);
                g_att[g_natt].link = link;
                ++g_natt;
                fprintf(stderr, "attached node-wide uprobe: %s\n", use);
            }
        }
        ++fresh;
        if (g_natt >= (int)(sizeof(g_att) / sizeof(g_att[0]))) {
            break;
        }
    }
    closedir(d);
    return fresh;
}

static int on_event(void* ctx, void* data, size_t len)
{
    struct daemon_ctx* d = ctx;
    if (len < sizeof(struct ssl_event)) {
        return 0;
    }
    const struct ssl_event* e = data;

    unsigned char* der = NULL;
    int der_len = 0;
    int is_pqc = 0;
    char group[64] = {0};
    int status = uds_get(d->agent_sock, d->dest, &der, &der_len, &is_pqc, group, sizeof(group));

    if (status == UDS_STATUS_OK) {
        int rc = inject_session(e->pid, (unsigned long)e->ssl, der, der_len);
        fprintf(stderr, "pid=%u ssl=%#llx dest=%s group=%s -> %s\n", e->pid,
                (unsigned long long)e->ssl, d->dest, group, rc == 0 ? "RESUMED" : "install-failed");
        free(der);
    }
    else {
        fprintf(stderr, "pid=%u dest=%s -> MISS, falling back to normal TLS (event)\n", e->pid,
                d->dest);
    }

    kill((pid_t)e->pid, SIGCONT); // always release the frozen thread
    return 0;
}

int main(int argc, char** argv)
{
    const char* agent_sock = NULL;
    const char* dest = NULL;
    const char* libssl = NULL;
    const char* exclude_comm = "ticket-agent";
    pid_t target = 0;
    int do_scan = 0;
    int dry_run = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--agent") && i + 1 < argc) {
            agent_sock = argv[++i];
        }
        else if (!strcmp(argv[i], "--dest") && i + 1 < argc) {
            dest = argv[++i];
        }
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            target = (pid_t)atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--libssl") && i + 1 < argc) {
            libssl = argv[++i];
        }
        else if (!strcmp(argv[i], "--exclude-comm") && i + 1 < argc) {
            exclude_comm = argv[++i];
        }
        else if (!strcmp(argv[i], "--scan")) {
            do_scan = 1;
        }
        else if (!strcmp(argv[i], "--dry-run")) {
            dry_run = 1;
            do_scan = 1;
        }
        else {
            fprintf(stderr,
                    "usage: %s --agent <sock> --dest <host:port> [--pid N | --scan] [--dry-run]\n",
                    argv[0]);
            return 2;
        }
    }
    if (target <= 0 && !do_scan) {
        fprintf(stderr, "specify --pid <N> or --scan\n");
        return 2;
    }

    pid_t self = getpid();

    // Dry run: discover and report only. No BPF, no freeze — safe anywhere.
    if (dry_run) {
        printf("injector --dry-run: discovering libssl processes (excluding comm '%s')\n",
               exclude_comm);
        int n = scan(NULL, self, 1);
        printf("%d distinct libssl file(s) would be probed\n", n);
        return 0;
    }

    if (!agent_sock || !dest) {
        fprintf(stderr, "missing --agent/--dest\n");
        return 2;
    }

    struct ssl_connect_bpf* skel = ssl_connect_bpf__open();
    if (!skel) {
        return 1;
    }
    skel->rodata->freeze = 1;
    snprintf((char*)skel->rodata->exclude_comm, sizeof(skel->rodata->exclude_comm), "%s",
             exclude_comm);
    // Ask the BPF program to report pids in our pid namespace, so /proc and ptrace
    // line up even when nested (kind: hostPID reaches only the node's ns).
    struct stat ns;
    if (stat("/proc/self/ns/pid", &ns) == 0) {
        skel->rodata->target_pidns_dev = ns.st_dev;
        skel->rodata->target_pidns_ino = ns.st_ino;
    }
    if (ssl_connect_bpf__load(skel)) {
        fprintf(stderr, "BPF load failed (need CAP_BPF/CAP_PERFMON)\n");
        return 1;
    }

    if (target > 0) {
        char libssl_buf[512];
        if (!libssl) {
            if (find_libssl_for_pid(target, libssl_buf, sizeof(libssl_buf)) != 0) {
                fprintf(stderr, "no libssl mapped in pid %d\n", target);
                return 1;
            }
            libssl = libssl_buf;
        }
        LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "SSL_connect");
        skel->links.on_ssl_connect =
            bpf_program__attach_uprobe_opts(skel->progs.on_ssl_connect, target, libssl, 0, &uo);
        if (!skel->links.on_ssl_connect) {
            fprintf(stderr, "uprobe attach failed on %s\n", libssl);
            return 1;
        }
        fprintf(stderr, "injector: watching pid %d (%s)\n", target, libssl);
    }
    else {
        int n = scan(skel->progs.on_ssl_connect, self, 0);
        fprintf(stderr, "injector: node-wide, %d libssl file(s) probed (excluding '%s')\n", n,
                exclude_comm);
    }

    struct daemon_ctx dctx = {.agent_sock = agent_sock, .dest = dest};
    struct ring_buffer* rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, &dctx, NULL);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int since_scan = 0;
    while (g_running) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -4 /* EINTR */) {
            break;
        }
        // Node-wide: periodically pick up newly-started libssl files (new pods).
        if (do_scan && ++since_scan >= 25) {
            scan(skel->progs.on_ssl_connect, self, 0);
            since_scan = 0;
        }
    }

    ring_buffer__free(rb);
    for (int i = 0; i < g_natt; ++i) {
        if (g_att[i].link) {
            bpf_link__destroy(g_att[i].link);
        }
    }
    ssl_connect_bpf__destroy(skel);
    return 0;
}
