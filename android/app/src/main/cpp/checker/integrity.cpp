#include <fcntl.h>
#include <link.h>
#include <string_view>
#include <unistd.h>

#include "integrity.h"
#include "logging.h"
#include "checker.h"

static uint32_t crc_table[256]{};

[[gnu::constructor(), gnu::used]]
void InitCrc() {
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (size_t j = 0; j < 8; j++) {
            if (c & 1) {
                c = polynomial ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        crc_table[i] = c;
    }
}

uint32_t Crc32(uint32_t initial, const void* buf, size_t len) {
    uint32_t c = initial ^ 0xFFFFFFFF;
    const auto* u = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len; ++i) {
        auto j = (c ^ u[i]) & 0xFF;
        c = crc_table[j] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

bool CompareTextSection(const proc_util::MapInfo& map) {
    bool res = true;
    int fd;
    ssize_t size;
    char* file_addr = nullptr;
    {
        fd = open(map.path.data(), O_RDONLY);
        if (fd < 0) {
            res = false;
            goto clean;
        }

        size = lseek(fd, 0, SEEK_END);
        if (size < 0) {
            res = false;
            goto clean;
        }


        file_addr = reinterpret_cast<char *>(mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (file_addr == MAP_FAILED) {
            res = false;
            goto clean;
        }

        auto start = map.start;

        auto ehdr = reinterpret_cast<ElfW(Ehdr)*>(file_addr);
        auto phdr = reinterpret_cast<ElfW(Phdr)*>(file_addr + ehdr->e_phoff);

        auto vaddr_min = (uintptr_t) -1;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD && phdr[i].p_vaddr < vaddr_min) vaddr_min = phdr[i].p_vaddr;
        }

        auto bias = start - vaddr_min;
        uintptr_t page_mask = getpagesize() - 1;
#define PageStart(x) ((x) & ~(page_mask))
#define PageEnd(x) (((x) + (page_mask)) & ~(page_mask))

        for (int i = 0; i < ehdr->e_phnum; i++) {
            auto &p = phdr[i];
            if (p.p_type == PT_LOAD && (p.p_flags & PF_X) != 0) {
                auto file_start = PageStart(reinterpret_cast<uintptr_t>(file_addr + p.p_offset));
                // assert filesz == memsz
                auto file_end = PageEnd(reinterpret_cast<uintptr_t>(file_addr + p.p_offset + p.p_memsz));
                auto crc_file = Crc32(0, reinterpret_cast<char*>(file_start), file_end - file_start);
                LOGD("Compare {} offset {:#x} ({:#x}-{:#x}) sz {}, file   crc {:#x}", map.path, p.p_offset, file_start, file_end, p.p_filesz,
                     crc_file);

                auto seg_addr = bias + p.p_vaddr;
                auto seg_start = PageStart(seg_addr);
                auto seg_end = PageEnd(seg_addr + p.p_memsz);
                auto sz = seg_end - seg_start;
                auto has_read = (p.p_flags & PF_R) != 0;
                if (mprotect(reinterpret_cast<void *>(seg_start), sz,PROT_READ | PROT_EXEC) == -1) {
                    PLOGE("set {:#x} {:#x} to rx:", seg_start, seg_end);
                }
                auto crc_memory = Crc32(0, reinterpret_cast<void *>(seg_start), sz);
                if (mprotect(reinterpret_cast<void *>(seg_start), sz, PROT_EXEC | (has_read ? PROT_READ : 0)) == -1) {
                    PLOGE("reset {:#x} {:#x} to {}x:", seg_start, seg_end, has_read ? 'r' : '-');
                }
                LOGD("Compare {} offset {:#x} ({:#x}-{:#x}), memory crc {:#x}", map.path, seg_addr, seg_start, seg_end,
                     crc_memory);
                if (crc_file != crc_memory) {
                    res = false;
                }
            }
        }
    }
    clean:
    if (fd != -1) close(fd);
    if (file_addr != MAP_FAILED) munmap(file_addr, size);
    return res;
}

extern "C" char __executable_start[];
extern "C" char _etext[];
extern "C" volatile unsigned long checksum = 0x04c696e6751696e67;

void SetWo() {
    auto ehdr = reinterpret_cast<ElfW(Ehdr)*>(__executable_start);
    auto phdr = reinterpret_cast<ElfW(Phdr)*>(__executable_start + ehdr->e_phoff);

    auto vaddr_min = (uintptr_t) -1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_vaddr < vaddr_min) vaddr_min = phdr[i].p_vaddr;
    }

    auto bias = __executable_start - vaddr_min;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        auto &p = phdr[i];
        if (p.p_type == PT_LOAD && (p.p_flags & PF_W) != 0) {
            auto addr = reinterpret_cast<uintptr_t>(bias + p.p_vaddr);
            auto end = addr + p.p_memsz;
            auto align = p.p_align - 1;
            auto aligned_addr = addr & ~align;
            auto aligned_end = (end + align) & ~align;
            auto real_sz = aligned_end - aligned_addr;
            LOGD("set wo {:x} {}", aligned_addr, real_sz);
            if (mprotect(reinterpret_cast<void*>(aligned_addr), real_sz, PROT_WRITE) == -1) {
                PLOGE("mprotect");
            }
        }
    }
}

