// symbols — see symbols.h. ELF64 only.

#define _GNU_SOURCE

#include "symbols.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// In /proc/<pid>/maps, find the library whose path contains lib_substr. Returns
// the segment-0 map base (the mapping at file offset 0) in *map_base and the
// target-namespace path in path_out. Returns 0 on success.
static int find_library(pid_t pid, const char* lib_substr, unsigned long* map_base, char* path_out,
                        size_t path_cap)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* f = fopen(maps_path, "r");
    if (f == NULL) {
        return -1;
    }

    int found = 0;
    unsigned long best_base = 0;
    int have_off0 = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long off = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %511[^\n]", &start, &end, perms, &off, path);
        if (n < 5 || path[0] != '/') {
            continue;
        }
        if (strstr(path, lib_substr) == NULL) {
            continue;
        }
        // Prefer the offset-0 mapping (segment 0, contains the ELF header); fall
        // back to the lowest-address mapping for the file.
        if (!found || (off == 0 && !have_off0) || (start < best_base && !have_off0)) {
            best_base = start;
            snprintf(path_out, path_cap, "%s", path);
        }
        if (off == 0) {
            best_base = start;
            have_off0 = 1;
        }
        found = 1;
    }
    fclose(f);
    if (!found) {
        return -1;
    }
    *map_base = best_base;
    return 0;
}

// mmap the ELF at target-namespace path (via /proc/<pid>/root), returning the
// mapping and setting *size. Returns NULL on failure.
static void* map_elf(pid_t pid, const char* path, size_t* size)
{
    char rooted[600];
    snprintf(rooted, sizeof(rooted), "/proc/%d/root%s", pid, path);
    int fd = open(rooted, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        // Fall back to the path in our own namespace (self / shared ns).
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return NULL;
        }
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return NULL;
    }
    void* base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        return NULL;
    }
    *size = (size_t)st.st_size;
    return base;
}

// Parse .dynsym for a defined symbol `sym`; return its st_value plus the p_vaddr
// of the segment mapped at file offset 0 (needed to turn map base into load
// bias). Returns 0 on success.
static int dynsym_lookup(const void* elf, size_t size, const char* sym, unsigned long* st_value,
                         unsigned long* base_vaddr)
{
    const unsigned char* p = elf;
    const Elf64_Ehdr* eh = elf;
    if (size < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64) {
        return -1;
    }

    // p_vaddr of the PT_LOAD covering file offset 0 (the load-bias reference).
    *base_vaddr = 0;
    const Elf64_Phdr* ph = (const Elf64_Phdr*)(p + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0) {
            *base_vaddr = ph[i].p_vaddr;
            break;
        }
    }

    // Locate .dynsym and its linked string table via the section headers.
    const Elf64_Shdr* sh = (const Elf64_Shdr*)(p + eh->e_shoff);
    const Elf64_Sym* syms = NULL;
    size_t nsyms = 0;
    const char* strtab = NULL;
    for (int i = 0; i < eh->e_shnum; ++i) {
        if (sh[i].sh_type == SHT_DYNSYM) {
            syms = (const Elf64_Sym*)(p + sh[i].sh_offset);
            nsyms = sh[i].sh_entsize ? sh[i].sh_size / sh[i].sh_entsize : 0;
            const Elf64_Shdr* link = &sh[sh[i].sh_link];
            strtab = (const char*)(p + link->sh_offset);
            break;
        }
    }
    if (syms == NULL || strtab == NULL) {
        return -1;
    }

    for (size_t i = 0; i < nsyms; ++i) {
        if (syms[i].st_shndx == SHN_UNDEF || syms[i].st_value == 0) {
            continue; // undefined import, not a definition here
        }
        const char* name = strtab + syms[i].st_name;
        if (strcmp(name, sym) == 0) {
            *st_value = syms[i].st_value;
            return 0;
        }
    }
    return -1;
}

unsigned long resolve_symbol(pid_t pid, const char* lib_substr, const char* sym)
{
    unsigned long map_base = 0;
    char path[512];
    if (find_library(pid, lib_substr, &map_base, path, sizeof(path)) != 0) {
        return 0;
    }

    size_t size = 0;
    void* elf = map_elf(pid, path, &size);
    if (elf == NULL) {
        return 0;
    }

    unsigned long st_value = 0;
    unsigned long base_vaddr = 0;
    int rc = dynsym_lookup(elf, size, sym, &st_value, &base_vaddr);
    munmap(elf, size);
    if (rc != 0) {
        return 0;
    }

    // runtime = load_bias + st_value; load_bias = map_base - base_vaddr.
    return map_base - base_vaddr + st_value;
}
