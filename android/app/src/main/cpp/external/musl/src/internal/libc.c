#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "libc.h"

#ifndef AT_NULL
#define AT_NULL 0
#endif

#ifndef AT_PAGESZ
#define AT_PAGESZ 6
#endif

#define FALLBACK_PAGE_SIZE 4096
#define MAX_SUPPORTED_PAGE_SIZE 65536

struct __libc __libc = {
    .page_size = FALLBACK_PAGE_SIZE,
};

size_t __hwcap;
char *__progname=0, *__progname_full=0;

struct auxv_entry {
    uintptr_t type;
    uintptr_t value;
};

static int valid_page_size(uintptr_t value) {
    return value >= FALLBACK_PAGE_SIZE &&
           value <= MAX_SUPPORTED_PAGE_SIZE &&
           (value & (value - 1)) == 0;
}

/*
 * Read AT_PAGESZ without calling into bionic during ELF constructor execution.
 * The TrustAttestor shared object provides its own syscall-backed open/read/close,
 * so this path does not depend on a manually resolved cross-DSO function pointer.
 */
static size_t read_kernel_page_size(void) {
    int fd = open("/proc/self/auxv", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FALLBACK_PAGE_SIZE;

    struct auxv_entry entry;
    unsigned char *cursor = (unsigned char *)&entry;
    size_t received = 0;

    for (;;) {
        ssize_t count = read(fd, cursor + received, sizeof(entry) - received);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (count == 0) break;

        received += (size_t)count;
        if (received != sizeof(entry)) continue;

        if (entry.type == AT_PAGESZ && valid_page_size(entry.value)) {
            close(fd);
            return (size_t)entry.value;
        }
        if (entry.type == AT_NULL) break;
        received = 0;
    }

    close(fd);
    return FALLBACK_PAGE_SIZE;
}

int getpagesize(void) {
    return (int)libc.page_size;
}

__attribute__((constructor(102), used)) void Init() {
    libc.page_size = read_kernel_page_size();
}

weak_alias(__progname, program_invocation_short_name);
weak_alias(__progname_full, program_invocation_name);
