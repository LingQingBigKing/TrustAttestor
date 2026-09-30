#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <elf.h>
#include <link.h>
#include <string_view>
#include <pthread.h>
#include <mntent.h>
#include <sys/system_properties.h>

class Elf {
    ElfW(Addr) bias_addr_ = 0;

    ElfW(Dyn) *dynamic_ = nullptr;  //.dynamic
    ElfW(Word) dynamic_size_ = 0;

    const char *dyn_str_ = nullptr;  //.dynstr (string-table)
    ElfW(Sym) *dyn_sym_ = nullptr;   //.dynsym (symbol-index to string-table's offset)

    // for ELF hash
    uint32_t *bucket_ = nullptr;
    uint32_t bucket_count_ = 0;
    uint32_t *chain_ = nullptr;

    // append for GNU hash
    uint32_t sym_offset_ = 0;
    ElfW(Addr) *bloom_ = nullptr;
    uint32_t bloom_size_ = 0;
    uint32_t bloom_shift_ = 0;

    bool valid_ = false;

    uint32_t GnuLookup(std::string_view name) const {
        static constexpr uint32_t kHashMask = 0xf0000000;
        static constexpr uint32_t kHashShift = 24;
        uint32_t hash = 0;
        uint32_t tmp;

        if (!bucket_ || bloom_) return 0;

        for (unsigned char chr : name) {
            hash = (hash << 4) + chr;
            tmp = hash & kHashMask;
            hash ^= tmp;
            hash ^= tmp >> kHashShift;
        }
        const char *strings = dyn_str_;

        for (auto idx = bucket_[hash % bucket_count_]; idx != 0; idx = chain_[idx]) {
            auto *sym = dyn_sym_ + idx;
            if (name == strings + sym->st_name) {
                return idx;
            }
        }
        return 0;
    }

    uint32_t ElfLookup(std::string_view name) const {
        static constexpr auto kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
        static constexpr uint32_t kInitialHash = 5381;
        static constexpr uint32_t kHashShift = 5;

        if (!bucket_ || !bloom_) return 0;

        uint32_t hash = kInitialHash;
        for (unsigned char chr : name) {
            hash += (hash << kHashShift) + chr;
        }

        auto bloom_word = bloom_[(hash / kBloomMaskBits) % bloom_size_];
        uintptr_t mask = 0 | uintptr_t{1} << (hash % kBloomMaskBits) |
                         uintptr_t{1} << ((hash >> bloom_shift_) % kBloomMaskBits);
        if ((mask & bloom_word) == mask) {
            auto idx = bucket_[hash % bucket_count_];
            if (idx >= sym_offset_) {
                const char *strings = dyn_str_;
                do {
                    auto *sym = dyn_sym_ + idx;
                    if (((chain_[idx] ^ hash) >> 1) == 0 && name == strings + sym->st_name) {
                        return idx;
                    }
                } while ((chain_[idx++] & 1) == 0);
            }
        }
        return 0;
    }

    uint32_t LinearLookup(std::string_view name) const {
        if (!dyn_sym_ || !sym_offset_) return 0;
        for (uint32_t idx = 0; idx < sym_offset_; idx++) {
            auto *sym = dyn_sym_ + idx;
            if (name == dyn_str_ + sym->st_name) {
                return idx;
            }
        }
        return 0;
    }
public:
    Elf(uintptr_t load_bias, const ElfW(Phdr)* program_headers, size_t program_header_count)
            : bias_addr_(load_bias) {
        if (load_bias == 0 || program_headers == nullptr ||
            program_header_count == 0 || program_header_count > 1024) {
            return;
        }

        for (size_t i = 0; i < program_header_count; ++i) {
            const auto *program_header = program_headers + i;
            if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
                // dlpi_addr is already the ELF load bias. A non-zero virtual
                // address for the first load segment does not need to be
                // subtracted a second time.
                if (program_header->p_vaddr > load_bias) {
                    return;
                }
            } else if (program_header->p_type == PT_DYNAMIC) {
                if (program_header->p_vaddr > UINTPTR_MAX - load_bias ||
                    program_header->p_memsz == 0 ||
                    program_header->p_memsz > 1024 * 1024) {
                    return;
                }
                dynamic_ = reinterpret_cast<decltype(dynamic_)>(
                        load_bias + program_header->p_vaddr);
                dynamic_size_ = program_header->p_memsz;
            }
        }
        if (!dynamic_) return;

        for (auto *dynamic = dynamic_, *dynamic_end = dynamic_ + (dynamic_size_ / sizeof(dynamic[0]));
             dynamic < dynamic_end; ++dynamic) {
            switch (dynamic->d_tag) {
                case DT_NULL:
                    // the end of the dynamic-section
                    dynamic = dynamic_end;
                    break;
                case DT_STRTAB: {
                    dyn_str_ = reinterpret_cast<decltype(dyn_str_)>(bias_addr_ + dynamic->d_un.d_ptr);
                    break;
                }
                case DT_SYMTAB: {
                    dyn_sym_ = reinterpret_cast<decltype(dyn_sym_)>(bias_addr_ + dynamic->d_un.d_ptr);
                    break;
                }
                case DT_HASH: {
                    // ignore DT_HASH when ELF contains DT_GNU_HASH hash table
                    if (bloom_) continue;
                    auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
                    bucket_count_ = raw[0];
                    bucket_ = raw + 2;
                    chain_ = bucket_ + bucket_count_;
                    break;
                }
                case DT_GNU_HASH: {
                    auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
                    bucket_count_ = raw[0];
                    sym_offset_ = raw[1];
                    bloom_size_ = raw[2];
                    bloom_shift_ = raw[3];
                    bloom_ = reinterpret_cast<decltype(bloom_)>(raw + 4);
                    bucket_ = reinterpret_cast<decltype(bucket_)>(bloom_ + bloom_size_);
                    chain_ = bucket_ + bucket_count_ - sym_offset_;
                    break;
                }
                default:
                    break;
            }
        }

        valid_ = dyn_str_ != nullptr && dyn_sym_ != nullptr &&
                 bucket_ != nullptr && bucket_count_ != 0;
    }
    bool Valid() const { return valid_; };

    void* dlsym(std::string_view name) {
        uint32_t idx = GnuLookup(name);
        if (!idx) idx = ElfLookup(name);
        if (!idx) idx = LinearLookup(name);
        if (!idx) return nullptr;
        return (char*) bias_addr_ + dyn_sym_[idx].st_value;
    }
};

#define DCL_INDIRECT_STUB(ret, name, ...) \
    ret (*libc_##name)(__VA_ARGS__) = nullptr;        \
    ret name(__VA_ARGS__)

DCL_INDIRECT_STUB(int*, __errno) {
    static int tmp_errno = 0;
    if (libc___errno) return libc___errno();
    return &tmp_errno;
}

DCL_INDIRECT_STUB(void*, malloc, size_t sz) {
    return libc_malloc(sz);
}

DCL_INDIRECT_STUB(void, free, void* a) {
    libc_free(a);
}

DCL_INDIRECT_STUB(void*, calloc, size_t s1, size_t s2) {
    return libc_calloc(s1, s2);
}

DCL_INDIRECT_STUB(void*, realloc, void* a, size_t s) {
    return libc_realloc(a, s);
}

DCL_INDIRECT_STUB(int, pthread_create, pthread_t* _Nonnull __pthread_ptr,
                  pthread_attr_t const* _Nullable __attr,
                  void* _Nonnull (* _Nonnull __start_routine)(void* _Nonnull), void* _Nullable a) {
    return libc_pthread_create(__pthread_ptr, __attr, __start_routine, a);
}

DCL_INDIRECT_STUB(int, pthread_detach, pthread_t __pthread) {
    return libc_pthread_detach(__pthread);
}

DCL_INDIRECT_STUB(int, pthread_mutex_destroy, pthread_mutex_t* _Nonnull __mutex) {
    return libc_pthread_mutex_destroy(__mutex);
}

DCL_INDIRECT_STUB(int, pthread_mutex_init, pthread_mutex_t* _Nonnull __mutex, const pthread_mutexattr_t* _Nullable __attr) {
    return libc_pthread_mutex_init(__mutex, __attr);
}

DCL_INDIRECT_STUB(int, pthread_mutex_lock, pthread_mutex_t* _Nonnull __mutex) {
    return libc_pthread_mutex_lock(__mutex);
}

DCL_INDIRECT_STUB(int, pthread_mutex_trylock, pthread_mutex_t* _Nonnull __mutex) {
    return libc_pthread_mutex_trylock(__mutex);
}

DCL_INDIRECT_STUB(int, pthread_mutex_unlock, pthread_mutex_t* _Nonnull __mutex) {
    return libc_pthread_mutex_unlock(__mutex);
}

DCL_INDIRECT_STUB(int, pthread_cond_broadcast ,pthread_cond_t* _Nonnull __cond) {
    return libc_pthread_cond_broadcast(__cond);
}

DCL_INDIRECT_STUB(int, pthread_cond_destroy, pthread_cond_t* _Nonnull __cond) {
    return libc_pthread_cond_destroy(__cond);
}

DCL_INDIRECT_STUB(int, pthread_cond_init, pthread_cond_t* _Nonnull __cond, const pthread_condattr_t* _Nullable __attr) {
    return libc_pthread_cond_init(__cond, __attr);
}

DCL_INDIRECT_STUB(int, pthread_cond_signal, pthread_cond_t* _Nonnull __cond) {
    return libc_pthread_cond_signal(__cond);
}

DCL_INDIRECT_STUB(int, pthread_cond_timedwait, pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _Nonnull __mutex, const struct timespec* _Nullable __timeout) {
    return libc_pthread_cond_timedwait(__cond, __mutex, __timeout);
}

DCL_INDIRECT_STUB(int, pthread_cond_wait, pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _Nonnull __mutex) {
    return libc_pthread_cond_wait(__cond, __mutex);
}

DCL_INDIRECT_STUB(int, pthread_attr_init, pthread_attr_t* _Nonnull __attr) {
    return libc_pthread_attr_init(__attr);
}

DCL_INDIRECT_STUB(int, pthread_attr_setdetachstate, pthread_attr_t* _Nonnull __attr, int __state) {
    return libc_pthread_attr_setdetachstate(__attr, __state);
}

DCL_INDIRECT_STUB(int, pthread_attr_destroy, pthread_attr_t* _Nonnull __attr) {
    return libc_pthread_attr_destroy(__attr);
}

DCL_INDIRECT_STUB(int, pthread_key_create, pthread_key_t* _Nonnull __key_ptr, void (* _Nullable __key_destructor)(void* _Nullable)) {
    return libc_pthread_key_create(__key_ptr, __key_destructor);
}

DCL_INDIRECT_STUB(int, pthread_key_delete, pthread_key_t __key) {
    return libc_pthread_key_delete(__key);
}

DCL_INDIRECT_STUB(int, pthread_setspecific, pthread_key_t __key, const void* _Nullable __value) {
    return libc_pthread_setspecific(__key, __value);
}

DCL_INDIRECT_STUB(struct mntent*, getmntent, FILE* fp) {
    return libc_getmntent(fp);
}

DCL_INDIRECT_STUB(int, endmntent, FILE* _Nullable fp) {
    return libc_endmntent(fp);
}

DCL_INDIRECT_STUB(FILE*, setmntent, const char* filename, const char* type) {
    return libc_setmntent(filename, type);
}

char **g_argv = nullptr;

struct LibcImage {
    uintptr_t load_bias = 0;
    const ElfW(Phdr)* program_headers = nullptr;
    size_t program_header_count = 0;
};

static int FindLibcImage(struct dl_phdr_info* info, size_t, void* opaque) {
    if (info == nullptr || opaque == nullptr || info->dlpi_name == nullptr ||
        info->dlpi_phdr == nullptr || info->dlpi_phnum == 0) {
        return 0;
    }

    const std::string_view path(info->dlpi_name);
    const size_t separator = path.find_last_of('/');
    const std::string_view name = separator == std::string_view::npos
            ? path : path.substr(separator + 1);
    if (name != "libc.so") return 0;

    bool has_dynamic = false;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            has_dynamic = true;
            break;
        }
    }
    if (!has_dynamic || info->dlpi_addr == 0) return 0;

    auto* image = static_cast<LibcImage*>(opaque);
    image->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
    image->program_headers = info->dlpi_phdr;
    image->program_header_count = info->dlpi_phnum;
    return 1;
}

__attribute__((constructor(101), used))
void init_indirect(int argc, char **argv) {
    g_argv = argv;
    LibcImage libc_image;
    dl_iterate_phdr(FindLibcImage, &libc_image);
    if (libc_image.load_bias == 0 || libc_image.program_headers == nullptr) _Exit(1);

    Elf elf{libc_image.load_bias, libc_image.program_headers,
            libc_image.program_header_count};
    if (!elf.Valid()) _Exit(1);
#define FIND_INDIRECT_SYM(sym) libc_##sym = reinterpret_cast<decltype(libc_##sym)>(elf.dlsym(#sym))
    FIND_INDIRECT_SYM(__errno);
    FIND_INDIRECT_SYM(malloc);
    FIND_INDIRECT_SYM(free);
    FIND_INDIRECT_SYM(calloc);
    FIND_INDIRECT_SYM(realloc);
    FIND_INDIRECT_SYM(pthread_create);
    FIND_INDIRECT_SYM(pthread_detach);
    FIND_INDIRECT_SYM(pthread_mutex_init);
    FIND_INDIRECT_SYM(pthread_mutex_lock);
    FIND_INDIRECT_SYM(pthread_mutex_destroy);
    FIND_INDIRECT_SYM(pthread_mutex_unlock);
    FIND_INDIRECT_SYM(pthread_mutex_trylock);
    FIND_INDIRECT_SYM(pthread_cond_broadcast);
    FIND_INDIRECT_SYM(pthread_cond_init);
    FIND_INDIRECT_SYM(pthread_cond_destroy);
    FIND_INDIRECT_SYM(pthread_cond_wait);
    FIND_INDIRECT_SYM(pthread_cond_signal);
    FIND_INDIRECT_SYM(pthread_cond_timedwait);
    FIND_INDIRECT_SYM(pthread_attr_destroy);
    FIND_INDIRECT_SYM(pthread_attr_init);
    FIND_INDIRECT_SYM(pthread_attr_setdetachstate);
    FIND_INDIRECT_SYM(pthread_key_create);
    FIND_INDIRECT_SYM(pthread_key_delete);
    FIND_INDIRECT_SYM(pthread_setspecific);
    FIND_INDIRECT_SYM(getmntent);
    FIND_INDIRECT_SYM(setmntent);
    FIND_INDIRECT_SYM(endmntent);
}
