#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <android/native_activity.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <ranges>
#include <string_view>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <thread>
#include <sys/utsname.h>
#include <cstdlib>
#include <fcntl.h>
#include <link.h>
#include <poll.h>

#include "android_runtime.hpp"
#include "checker_internal.h"
#include "elf_util.h"
#include "integrity.h"
#include "jni_helper.h"
#include "logging.h"
#include "utils.h"
#include "proc_util.hpp"
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include "api/_system_properties.h"
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <mntent.h>

#include <sys/uio.h>

using namespace std::string_literals;
using namespace std::string_view_literals;

// Detection-only module. UI state and external JNI entry points remain in checker.cpp.

constexpr auto kLinker = "linker64";
constexpr auto kStagefright = "libstagefright.so";
constexpr auto kNativeBridge = "libnativebridge.so";
constexpr auto kSymbolANetwork = "_ZN7android15ANetworkSession10threadLoopEv";
constexpr auto kSymbolNativeBridgeError = "NativeBridgeError";
constexpr auto kSymbolNativeBridgeErrorLegacy = "_ZN7android17NativeBridgeErrorEv";
constexpr auto kLSPHooker = "LSPHooker";
constexpr auto kKr328Magic = "kr328.magic";
constexpr auto kAndroidRuntime = "libandroid_runtime.so";
constexpr auto kSymbolGetRuntime = "_ZN7android14AndroidRuntime10getRuntimeEv";
constexpr auto kSymbolSoList = "__dl__ZL6solist";
constexpr auto kSymbolSoMain = "__dl__ZL6somain";
constexpr auto kSymbolVdSo = "__dl__ZL4vdso";
constexpr auto kSymbolRealPath = "__dl__ZNK6soinfo12get_realpathEv";
constexpr auto kSymSoinfoAllocator = "__dl__ZL18g_soinfo_allocator";

static size_t solist_next_offset = 0x30;

struct soinfo;

soinfo *solist = nullptr;
soinfo *somain = nullptr;
soinfo *vdso = nullptr;

static const char *(*get_realpath_sym)(soinfo *) = nullptr;

struct soinfo {
    soinfo *next() {
        return *(soinfo **) ((uintptr_t) this + solist_next_offset);
    }

    const char *get_realpath() {
        return get_realpath_sym(this);
    }
};

struct LinkerBlockAllocatorPage {
    LinkerBlockAllocatorPage *next;
};

struct LinkerBlockAllocator {
    size_t block_size_;
    LinkerBlockAllocatorPage* page_list_;
    void* free_block_list_;
    size_t allocated_;
};

struct LinkerTypeAllocator {
    LinkerBlockAllocator block_allocator_;
};

LinkerTypeAllocator *g_soinfo_allocator = nullptr;

void InitProperties() {
    if (ss::__system_properties_init()) {
        LOGE("failed to init properties");
        MarkProbeUnavailable(1, "runtime.system_properties.init");
    }
}

void InitSymbolList() {
    static bool initialized = false;
    if (initialized && !sSymbolList.empty()) return;
    auto libs = std::vector<std::string>();
    auto maps = proc_util::MapInfo::Scan();
    for (auto& item: maps) {
        if ((item.path.starts_with("/system/") || item.path.starts_with("/apex/")) &&
            (item.path.ends_with(".so") || item.path.find("/bin") != std::string::npos) &&
            access(item.path.data(), R_OK) == 0) {
            libs.emplace_back(item.path);
        }
        if (item.path == "[stack]") {
            gStackStart = item.start;
            gStackEnd = item.end;
        }
    }
    std::sort(libs.begin(), libs.end());
    libs.erase(std::unique(libs.begin(), libs.end()), libs.end());

    for (const auto& lib : libs) {
        if (!lib.ends_with(kNativeBridge) && !lib.ends_with(kStagefright) &&
            !lib.ends_with(kAndroidRuntime) && !lib.ends_with(kLinker)) {
            continue;
        }
        auto elf = SandHook::ElfImg(lib);
        if (lib.ends_with(kNativeBridge)) {
            auto symbol = kSymbolNativeBridgeError;
            auto addr = elf.getSymbAddress(symbol);
            if (addr == nullptr) {
                addr = elf.getSymbAddress(kSymbolNativeBridgeErrorLegacy);
            }
            sSymbolList.try_emplace(std::string(symbol), addr);
            LOGI("Init symbol NativeBridgeError at {}", addr);
        } else if (lib.ends_with(kAndroidRuntime)) {
            auto symbol = kSymbolGetRuntime;
            auto addr = elf.getSymbAddress(symbol);
            sSymbolList.try_emplace(std::string(symbol), addr);
            LOGI("Init symbol GetRuntime at {}", addr);
        } else if (lib.ends_with(kStagefright)) {
            auto symbol = kSymbolANetwork;
            auto addr = elf.getSymbAddress(symbol);
            sSymbolList.try_emplace(std::string(symbol), addr);
            LOGI("Init symbol threadLoop at {}", addr);
        } else if (lib.ends_with(kLinker)) {
            get_realpath_sym = reinterpret_cast<decltype(get_realpath_sym)>(elf.getSymbPrefixFirstAddress(kSymbolRealPath));
            auto addr = reinterpret_cast<soinfo**>(elf.getSymbPrefixFirstAddress(kSymbolSoList));
            solist = addr == nullptr ? nullptr : *addr;
            addr = reinterpret_cast<soinfo**>(elf.getSymbPrefixFirstAddress(kSymbolSoMain));
            somain = addr == nullptr ? nullptr : *addr;
            addr = reinterpret_cast<soinfo**>(elf.getSymbPrefixFirstAddress(kSymbolVdSo));
            vdso = addr == nullptr ? nullptr : *addr;
            g_soinfo_allocator = reinterpret_cast<LinkerTypeAllocator*>(elf.getSymbPrefixFirstAddress(kSymSoinfoAllocator));
        }
    }
    initialized = !sSymbolList.empty();
}

namespace {

struct PublicLinkerInventory {
    std::unordered_set<std::string> object_names;
};

int CollectPublicLinkerObject(dl_phdr_info* info, size_t, void* cookie) {
    if (info == nullptr || cookie == nullptr || info->dlpi_name == nullptr ||
        info->dlpi_name[0] == '\0') {
        return 0;
    }
    auto* inventory = static_cast<PublicLinkerInventory*>(cookie);
    std::string_view path(info->dlpi_name);
    auto slash = path.find_last_of('/');
    auto name = path.substr(slash == std::string_view::npos ? 0 : slash + 1);
    if (!name.empty()) inventory->object_names.emplace(name);
    return 0;
}

std::string_view MappedObjectName(std::string_view path) {
    auto deleted = path.find(" (deleted)");
    if (deleted != std::string_view::npos) path = path.substr(0, deleted);
    auto slash = path.find_last_of('/');
    auto name = path.substr(slash == std::string_view::npos ? 0 : slash + 1);
    if (name.ends_with(".so")) return name;
    return {};
}

bool IsLinkerManagedPath(std::string_view path) {
    return path.starts_with("/system/") || path.starts_with("/apex/") ||
           path.starts_with("/data/app/") || path.starts_with("/data/user/");
}

void FindUnloadViaPublicLinkMap() {
    PublicLinkerInventory inventory;
    dl_iterate_phdr(CollectPublicLinkerObject, &inventory);
    if (inventory.object_names.empty()) {
        LOGW("FindUnload public fallback unavailable: dl_iterate_phdr returned no objects");
        return;
    }

    size_t mapped_objects = 0;
    size_t unmatched_objects = 0;
    std::unordered_set<std::string> checked;
    for (const auto& item : proc_util::MapInfo::Scan()) {
        if ((item.perms & PROT_EXEC) == 0 || !IsLinkerManagedPath(item.path)) continue;
        auto name = MappedObjectName(item.path);
        if (name.empty() || name == "linker64" || name == "linker") continue;
        if (!checked.emplace(std::string(name)).second) continue;
        ++mapped_objects;
        if (!inventory.object_names.contains(std::string(name))) {
            ++unmatched_objects;
            LOGW("FindUnload public fallback: executable mapping is absent from dl_iterate_phdr: {}",
                 item.path);
        }
    }

    LOGI("FindUnload public fallback: loaded={} mapped={} unmatched={}",
         inventory.object_names.size(), mapped_objects, unmatched_objects);
    // A single mapping can be a platform-specific linker namespace detail. Two
    // independent missing objects are required before treating it as a hidden
    // soinfo/unload condition.
    if (unmatched_objects >= 2) {
        LOGE("FindUnload public fallback: multiple mapped libraries are absent from linker list");
        MarkInjection(4);
    }
}

} // namespace

int GetAndroidApiLevel() {
    static auto kApiLevel = []() {
        std::array<char, PROP_VALUE_MAX> prop_value{};
        ss::__system_property_get("ro.build.version.sdk", prop_value.data());
        int base = atoi(prop_value.data());
        ss::__system_property_get("ro.build.version.preview_sdk", prop_value.data());
        return base + atoi(prop_value.data());
    }();
    return kApiLevel;
}

void FindUnload() {
    if (!somain || !solist || !get_realpath_sym) {
        LOGW("FindUnload using public linker fallback: private symbols are incomplete");
        FindUnloadViaPublicLinkMap();
        return;
    }
    if (!g_soinfo_allocator) {
        // Android 17 no longer exposes the old global soinfo allocator.  The
        // linked-list and public-loader cross-check still provides coverage.
        LOGI("FindUnload using Android 17 linker-list fallback: allocator symbol unavailable");
        FindUnloadViaPublicLinkMap();
        return;
    }
    bool found_next_offset = false;
    for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
        auto *possible_next = *(void **) ((uintptr_t) solist + i * sizeof(void *));
        if (possible_next == somain || (vdso != nullptr && possible_next == vdso)) {
            solist_next_offset = i * sizeof(void *);
            found_next_offset = true;
            break;
        }
    }
    if (!found_next_offset) {
        LOGW("FindUnload using public linker fallback: soinfo next offset was not found");
        FindUnloadViaPublicLinkMap();
        return;
    }
    soinfo* first = solist->next();
    if (first == nullptr) {
        LOGW("FindUnload using public linker fallback: soinfo list is empty");
        FindUnloadViaPublicLinkMap();
        return;
    }
    size_t soinfo_size = g_soinfo_allocator->block_allocator_.block_size_;
    LOGD("soinfo size {}", soinfo_size);
    uintptr_t first_page = reinterpret_cast<uintptr_t>(first) - 16;
    std::vector<uintptr_t> pages;
    // reversed order
    for (auto p = g_soinfo_allocator->block_allocator_.page_list_; p; p = p->next) {
        pages.push_back((uintptr_t) p);
        if (p->next == nullptr && (uintptr_t) p != first_page) {
            LOGE("first page not patch");
            MarkProbeUnavailable(1, "runtime.soinfo.page_chain");
            return;
        }
    }
    std::reverse(pages.begin(), pages.end());
    LOGD("total {} pages", pages.size());
    size_t pn = 0, i = 0;
    size_t num_per_page = 0;

#ifndef NDEBUG
    FILE* dbg = fopen("/data/data/com.lingqing.trustattestor/files/soinfo.txt", "w");
    if (!dbg) PLOGE("open soinfo.txt");
    else {
        fprintf(dbg, "total %d pages\n", pages.size());
        int j = 0;
        for (auto page_start: pages) {
            fprintf(dbg, "page %d: %p\n", j, page_start);
            j++;
        }
    }
#endif

    bool stop = false;
    bool found_android = false;
    bool found_soundpool = false;

    for (auto so = first; so != nullptr; so = so->next()) {
        auto required_addr = pages[pn] + 16 + i * soinfo_size;
        std::string_view path{so->get_realpath()};
        if (required_addr != reinterpret_cast<uintptr_t>(so)) {
            bool abnormal = true;
            if (pn == 0 && num_per_page == 0 && pages.size() > 1) {
                // try next page
                pn = 1;
                num_per_page = i;
                i = 0;
                required_addr = pages[pn] + 16 + i * soinfo_size;
                abnormal = required_addr != reinterpret_cast<uintptr_t>(so);
            }
            if (abnormal && !stop) {
                MarkInjection(4);
                LOGE("found abnormal {} soinfo address {}", i, path);
#ifdef NDEBUG
                break;
#endif
            }
        }

#ifndef NDEBUG
        if (dbg) {
            fprintf(dbg, "soinfo %016x page=%02d idx=%03d required=%016x normal=%s path=%s\n",
                    so, pn, i, required_addr,
                    (required_addr == reinterpret_cast<uintptr_t>(so)) ? "true " : "false",
                    path.data()
                    );
        }
#endif

        if (path.ends_with("/libandroid.so")) {
            // libandroid.so is in public.libraries.txt so it will always be loaded.
            // https://cs.android.com/android/platform/superproject/main/+/main:system/core/rootdir/etc/public.libraries.android.txt;l=2;drc=716ff7b55adf56b212974ea98783422b5682251f
            // frameworks/base/native/android/
            found_android = true;
        }

        if (path.ends_with("/libsoundpool.so")) {
            // libsoundpool.so is used for preloaded-classes so it is always loaded
            // also its name is stable and relative position is stable across different api
            found_soundpool = true;
        }

        if (found_android && found_soundpool) {
#ifdef NDEBUG
            break;
#else
            stop = true;
#endif
        }

        i++;
        if (num_per_page != 0 && i == num_per_page) {
            i = 0;
            pn++;
            if (pn >= pages.size()) {
                LOGE("reached last page");
                MarkProbeUnavailable(1, "runtime.soinfo.traversal");
                break;
            }
        }
    }
#ifndef NDEBUG
    if (dbg) fclose(dbg);
#endif
}

RINLINE void FindPtyPermissionLoophole(JNIEnv *env) {
    // https://github.com/tiann/KernelSU/blob/3750e6e759712b8f3e02678493ab435be39f7310/kernel/selinux/rules.c#L134
    // allow system_server untrusted_app_all_devpts chr_file { read, write }
    constexpr int SHELL_COMMAND_TRANSACTION = ('_' << 24) | ('C' << 16) | ('M' << 8) | 'D';
    auto ptmx = posix_openpt(O_RDWR);
    if (ptmx < 0) {
        PLOGE("open ptmx failed");
        return;
    }

    grantpt(ptmx);
    unlockpt(ptmx);

    auto pts = ptsname(ptmx);
    auto sin = open(pts, O_RDWR | O_NOCTTY);
    auto sout = dup(sin);
    auto serr = dup(sin);
    LOGD("send pty: pts {} in={} out={} err={}", pts, sin, sout, serr);

    auto binder = env->CallStaticObjectMethod(cl_service_manager, mid_get_service, env->NewStringUTF("package"));
    auto send = env->CallStaticObjectMethod(cl_parcel, mid_obtain);
    auto reply = env->CallStaticObjectMethod(cl_parcel, mid_obtain);

    auto fin = env->NewObject(cl_file_descriptor, mid_file_descriptor_cstr, sin);
    auto fout = env->NewObject(cl_file_descriptor, mid_file_descriptor_cstr, sout);
    auto ferr = env->NewObject(cl_file_descriptor, mid_file_descriptor_cstr, serr);

    env->CallVoidMethod(send, mid_write_file_descriptor, fin);
    env->CallVoidMethod(send, mid_write_file_descriptor, fout);
    env->CallVoidMethod(send, mid_write_file_descriptor, ferr);
    env->CallVoidMethod(send, mid_write_int, 1);
    env->CallVoidMethod(send, mid_write_string, env->NewStringUTF("path"));
    env->CallVoidMethod(send, mid_write_strong_binder, nullptr);
    env->CallVoidMethod(send, mid_write_strong_binder, nullptr);
    env->CallBooleanMethod(binder, mid_transact, SHELL_COMMAND_TRANSACTION, send, reply, 0);
    bool normal = false;
    if (auto exception = env->ExceptionOccurred()) {
        env->ExceptionClear();
        // We expected DeadObjectException
        // This only happens when fd cannot be sent, or system server died, which is impossible
        // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/jni/android_util_Binder.cpp;l=957;drc=9a856d325ca155c806d7efd9acec6d30452e69b2
        if (env->IsInstanceOf(exception, env->FindClass("android/os/DeadObjectException"))) {
            LOGD("send pty failed");
            normal = true;
        }
    }
    if (!normal) {
        LOGE("send pty success!!!");
        MarkPermissionLoophole();
    }
    env->CallVoidMethod(send, mid_recycle);
    env->CallVoidMethod(reply, mid_recycle);

    close(sin);
    close(sout);
    close(serr);
    close(ptmx);
}

void FindPermissionLoophole(JNIEnv *env) {
    FindPtyPermissionLoophole(env);
    if (GetAndroidApiLevel() < 30) return;
    int fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd == -1) return;
    struct NetlinkMessage {
        nlmsghdr hdr;
        rtgenmsg msg;
    } request;
    memset(&request, 0, sizeof(request));
    request.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    request.hdr.nlmsg_type = RTM_GETLINK;
    request.hdr.nlmsg_len = sizeof(request);
    request.msg.rtgen_family = AF_UNSPEC;
    bool success = TEMP_FAILURE_RETRY(send(fd, &request, sizeof(request), 0)) == sizeof(request);
    close(fd);

    if (success) {
        MarkPermissionLoophole();
    }
}

void FindNativeBridge() {
    do {
        auto symbol = kSymbolNativeBridgeError;
        auto NativeBridgeError = sSymbolList[std::string(symbol)];
        if (!NativeBridgeError) {
            LOGE("NativeBridgeError not found!!!");
            MarkProbeUnavailable(1, "runtime.native_bridge.symbol");
            break;
        }

        if (reinterpret_cast<bool (*)()>(NativeBridgeError)()) {
            LOGE("Found native bridge!!!");
            MarkInjection(4);
        }
    } while (false);

    do {
        auto symbol = kSymbolGetRuntime;
        auto GetRuntime = reinterpret_cast<AndroidRuntime*(*)()>(sSymbolList[std::string(symbol)]);
        if (!GetRuntime) {
            LOGE("GetRuntime not found!!!");
            MarkProbeUnavailable(1, "runtime.android_runtime.entry_symbol");
            break;
        }

        auto runtime = GetRuntime();
        if (!runtime) {
            MarkProbeUnavailable(1, "runtime.android_runtime.instance");
            break;
        }
        auto options = runtime->options();
        if (!options) {
            MarkProbeUnavailable(1, "runtime.java_vm.arguments");
            break;
        }

        auto idx = options->size() - 1;
        uintptr_t addr = (uintptr_t) reinterpret_cast<const JavaVMOption *>(options->itemLocation(
                idx))->optionString;
        if (!(addr >= gStackStart && addr < gStackEnd)) {
            // fingerprintBuf if presented, it's not on stack
            LOGD("skip fingerprintBuf");
            idx--;
        }
        char buf[PROP_VALUE_MAX] = {0};
        auto prop1 = "persist.debug.dalvik.vm.core_platform_api_policy";
        ss::__system_property_get(prop1, buf);
        if (buf[0] != 0) {
            LOGD("skip corePlatformApiPolicyBuf");
            idx--;
        }
        buf[0] = 0;
        auto prop2 = "dalvik.vm.zygote.max-boot-retry";
        ss::__system_property_get(prop2, buf);
        if (buf[0] != 0) {
            LOGD("skip dalvik.vm.zygote.max-boot-retry");
            idx--;
        }
        LOGD("found idx {}", idx);
        auto cpuAbiListBuf = reinterpret_cast<const JavaVMOption *>(options->itemLocation(
                idx))->optionString;
        idx--;
        auto maybeNativeBridgeLibrary = reinterpret_cast<const JavaVMOption *>(options->itemLocation(
                idx))->optionString;
        auto diff = maybeNativeBridgeLibrary - cpuAbiListBuf;
        LOGD("maybeNativeBridgeLibrary {} - cpuAbiListBuf {} = {}", cpuAbiListBuf,
             maybeNativeBridgeLibrary, diff);
        auto has_nb = diff == 0x70;
        if (has_nb) {
            LOGD("Found NativeBridge by lovesy!!!");
            MarkInjection(4);
        }
    } while (false);
}

void FindInconsistentMount() {
    char buf[PATH_MAX] = {0};
    struct statfs st1{}, st2{};
    readlink("/proc/self/exe", buf, PATH_MAX);
    statfs("/proc/self/exe", &st1);
    statfs(buf, &st2);
    // umount, direct statfs (overlayfs) vs readlink statfs (erofs)
    if (st1.f_type != st2.f_type) {
        LOGE("Inconsistent mount: {} <-> {}!!!", st1.f_type, st2.f_type);
        MarkInconsistentMount();
        return;
    }
    // no umount, both overlayfs, check mountinfo for overlayfs entry
    if (st1.f_type == OVERLAYFS_SUPER_MAGIC) {
        FILE* fp = fopen("/proc/self/mountinfo", "r");
        char line[PATH_MAX];
        while (fgets(line, PATH_MAX, fp)) {
            std::string_view line_sv(line);
            if ((line_sv.find(" /system ") != std::string_view::npos &&
                line_sv.find(" overlay ") != std::string_view::npos) ||
                (line_sv.find(" /system/bin ") != std::string_view::npos &&
                line_sv.find(" overlay ") != std::string_view::npos)) {
                fclose(fp);
                return;
            }
        }
        fclose(fp);
        LOGE("Inconsistent mount: found OVERLAYFS_SUPER_MAGIC but no overlayfs mount found!");
        MarkInconsistentMount();
    }
}

extern char** g_argv;

void FindMemory() {
    auto maps = proc_util::MapInfo::Scan();
    ino_t jit_cache = 0, jit_zygote_cache = 0, jit_cache_read = 0;
    auto anon_jit_zygote_cache = 0, api = GetAndroidApiLevel();
    for (auto& item: maps) {
        if (item.perms & PROT_EXEC) {
            if (item.path.starts_with("[") && !item.path.starts_with("[anon:")) {
                continue;
            }
            // Only Android 10 maps jit-zygote-cache to anon memory
            if (api == 29 && item.path == "[anon:dalvik-zygote-jit-code-cache]") {
                // There should be only one section with x permission
                if (anon_jit_zygote_cache) {
                    LOGE("Inconsistent dalvik-zygote-jit-code-cache!!!");
                    MarkInjection(1);
                }
                ++anon_jit_zygote_cache;
                continue;
            }
            if (item.path.starts_with("/dev/zero") || !item.path.starts_with('/')) {
                LOGE("Found suspicious anonymous memory at {:#x}!!!", item.start);
                MarkInjection(2);
                continue;
            }
            if (item.path.starts_with("/memfd:jit-cache") ||
                item.path.starts_with("/dev/ashmem/jit-cache") ||
                item.path.starts_with("/memfd:/jit-cache") ||
                item.path.starts_with("/dev/ashmem//jit-cache") ||
                item.path.starts_with("/dev/ashmem/dalvik-jit-code-cache")) {
                if (jit_cache && item.inode != jit_cache) {
                    LOGE("Inconsistent jit-cache!!!");
                    MarkInjection(1);
                }
                jit_cache = item.inode;
                continue;
            }
            if (item.path.starts_with("/memfd:jit-zygote-cache") ||
                item.path.starts_with("/dev/ashmem/jit-zygote-cache") ||
                item.path.starts_with("/memfd:/jit-zygote-cache") ||
                item.path.starts_with("/dev/ashmem//jit-zygote-cache")) {
                if (jit_zygote_cache && item.inode != jit_zygote_cache) {
                    LOGE("Inconsistent jit-zygote-cache!!!");
                    MarkInjection(1);
                }
                jit_zygote_cache = item.inode;
                continue;
            }
            // Rest: starts_with('/') && !starts_with('/dev/zero') && !jit-cache
            struct stat st{};
            stat(item.path.data(), &st);
            if (item.inode != st.st_ino) {
                LOGE("Found inconsistent mapping!!! {}", item.path);
                MarkInjection(1);
            }
        }
        if (item.perms & PROT_READ) {
            // Zygisk-Fontloader will map font files to jit-cache, check inconsistency
            if (item.path.starts_with("/memfd:jit-cache")) {
                if (jit_cache_read && item.inode != jit_cache_read) {
                    LOGE("Inconsistent jit-cache(read)!!!");
                    MarkInjection(1);
                }
                jit_cache_read = item.inode;
                continue;
            }
            // Check preloaded jars
            if (item.path.starts_with("/system/framework/framework.jar")) {
                struct stat st{};
                stat(item.path.data(), &st);
                // Device id is unreliable on overlayfs
                // https://github.com/torvalds/linux/commit/3efdc78fdc21ab82694707eb234ab93f28d13ba8
                if (item.inode != st.st_ino) {
                    LOGE("Found inconsistent inode!!! {}", item.path);
                    MarkFutileHide(1u << 4);
                }
                continue;
            }
        }
        // Old ZygiskNext which leaks entry on stack
        if (item.path == "[stack]") {
            auto d = reinterpret_cast<uintptr_t*>(g_argv);
            LOGD("argv: {}", (uintptr_t) d);
            if (!((uintptr_t) (d - 7) >= item.start && (uintptr_t) (d - 6) < item.end)) {
                LOGE("argv is not in stack!!!");
                continue;
            }
            // old zn:
            // entry   |
            //[/debug_r]amdisk/l
            // ib64/lib|zygisk.s
            // o       |
            // argc    |argv

            // vietnam:
            // zygisk_i|nject_en
            //[try     ]
            // /debug_r|amdisk/m
            // agisk64 |
            // argc    |argv
            auto val = *(d - 7);
            LOGD("*(argv-7) = {}", val);
            if (val == 0x797274 /*try*/ || val == 0x725f67756265642f /*/debug_r*/) {
                LOGE("found argv-7 !!!");
                MarkInjection(4);
            }
        }
        // Find odex with inline max code units argument
        if (item.path.find("com.lingqing.trustattestor") != std::string::npos && item.path.ends_with(".odex")) {
            static constexpr auto str = "inline-max-code-units=";
            std::string_view odex(reinterpret_cast<const char *>(item.start), item.end - item.start);
            if (odex.find(str) != std::string_view::npos) {
                LOGE("Found inline-max-code-units=0!!!");
                MarkFutileHide(1u << 5);
            }
        }
    }
}

int GetFileCon(const char *path, std::string &ctx) {
    std::array<char, 1024> buf{};
    auto rc = static_cast<int>(syscall(
            __NR_lgetxattr, path, "security.selinux", buf.data(), buf.size() - 1));
    if (rc >= 0) {
        size_t length = static_cast<size_t>(rc);
        while (length > 0 && buf[length - 1] == '\0') --length;
        ctx.assign(buf.data(), length);
    }
    return rc;
}

RINLINE bool CheckAreaPerm(const char *name) {
    std::string ctx;
    struct stat s{};
    auto path = std::string("/dev/__properties__/") + name;
    if (stat(path.c_str(), &s) == 0 && ((s.st_mode & 07777) != 0444 || s.st_uid != 0 || s.st_gid != 0)) {
        LOGW("{} perm is not 444 or uid / gid not 0: {} {} {}", name, s.st_mode, s.st_uid, s.st_gid);
        return true;
    }
    if (GetFileCon(path.c_str(), ctx) >= 0) {
        if (ctx != name) {
            LOGW("{} name != context", name);
            return true;
        }
    }
    return false;
}

RINLINE bool ScanArea(ss::prop_area *area, const char *name) {
    uint32_t end;
    std::vector<std::pair<uint32_t, uint32_t>> v;
    area->report_obj_allocation([](uint32_t start, uint32_t length, void* cookie) {
                                    auto l = reinterpret_cast<std::vector<std::pair<uint32_t, uint32_t>>*>(cookie);
                                    l->push_back({start, length});
                                }, &v, &end
    );
    v.push_back({end, 0});
    if (GetAndroidApiLevel() >= 30) {
        // https://cs.android.com/android/_/android/platform/bionic/+/0cf90556de2bde53a1957c5946036b2fe2e4e429
        // there is no dirty backup before android 11
        v.push_back({sizeof(ss::prop_bt), __BIONIC_ALIGN(PROP_VALUE_MAX, sizeof(uint_least32_t))});
    }
    std::sort(v.begin(), v.end());
    bool found = false;
    for (auto i = 0u; i < v.size() - 1; i++) {
        auto &s1 = v[i], &s2 = v[i + 1];
        if (s1.first == s2.first || s1.first + s1.second > s2.first) {
            // overlaps
            MarkProbeUnavailable(1, "system.property.area_layout");
            return false;
        } else if (s1.first + s1.second < s2.first) {
            LOGE("found hole at context {} {} {}", name, s1.first, s2.first);
            found = true;
        }
    }
    return found;
}

void FindResetProp() {
    static const std::set<std::string_view> detects {
            "ro.boot.vbmeta.device_state", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
            "ro.boot.veritymode", "ro.boot.warranty_bit", "ro.warranty_bit",
            "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
            "ro.vendor.boot.warranty_bit", "ro.vendor.warranty_bit",
            "vendor.boot.vbmeta.device_state", "vendor.boot.verifiedbootstate",
            "ro.bootmode", "ro.boot.mode", "vendor.boot.mode",
            "ro.dalvik.vm.native.bridge",
    };
    auto contexts = ss::__system_property_get_contexts();
    contexts->ForEachContext([](ss::prop_area* area, const char* name, void*) {
        if (CheckAreaPerm(name) || ScanArea(area, name)) {
            LOGE("Found abnormal prop area {}", name);
            AddPropertyAreaModified();
        }
    }, nullptr);
    ss::__system_property_foreach([](const ss::prop_info *pi, auto *) {
        uint32_t serial;
        if (detects.contains(pi->name) &&
            ((serial = __system_property_serial(pi)) & pi->kLongFlag) == 0 &&
            (serial & 0x00fffffe) != 0) {
            LOGE("Found abnormal prop serial {}", pi->name);
            AddPropertyItemModified();
        }
        if (detects.contains(pi->name) && !pi->is_long() && std::string_view(pi->name).starts_with("ro.")) {
            bool end = false;
            bool char_after_end = false;
            for (int i = 0; i < PROP_VALUE_MAX; i++) {
                if (!end) {
                    if (pi->value[i] == 0) end = true;
                } else {
                    if (pi->value[i] != 0) {
                        char_after_end = true;
                        break;
                    }
                }
            }
            if (!end || char_after_end) {
                LOGE("Found abnormal prop remains {}", pi->name);
                AddPropertyItemModified();
            }
        }
    }, nullptr);
}

void FindSystemServer(JNIEnv* env) {
    constexpr int SHELL_COMMAND_TRANSACTION = ('_' << 24) | ('C' << 16) | ('M' << 8) | 'D';
    auto binder = env->CallStaticObjectMethod(cl_service_manager, mid_get_service, env->NewStringUTF("package"));
    auto send = env->CallStaticObjectMethod(cl_parcel, mid_obtain);
    auto reply = env->CallStaticObjectMethod(cl_parcel, mid_obtain);
    auto j_stdin = env->GetStaticObjectField(cl_file_descriptor, fid_stdin);
    auto pipe = (jobjectArray) env->CallStaticObjectMethod(cl_parcel_file_descriptor, mid_create_pipe);
    auto pfd_read = env->GetObjectArrayElement(pipe, 0);
    auto pfd_write = env->GetObjectArrayElement(pipe, 1);
    auto fd_send = env->CallObjectMethod(pfd_write, mid_get_file_descriptor);
    int fd_recv = env->CallIntMethod(pfd_read, mid_get_fd);
    env->CallVoidMethod(send, mid_write_file_descriptor, j_stdin);
    env->CallVoidMethod(send, mid_write_file_descriptor, fd_send);
    env->CallVoidMethod(send, mid_write_file_descriptor, fd_send);
    env->CallVoidMethod(send, mid_write_int, 1);
    env->CallVoidMethod(send, mid_write_string, env->NewStringUTF("path"));
    env->CallVoidMethod(send, mid_write_strong_binder, nullptr);
    env->CallVoidMethod(send, mid_write_strong_binder, nullptr);
    env->CallBooleanMethod(binder, mid_transact, SHELL_COMMAND_TRANSACTION, send, reply, 0);
    std::string buf(10240, '\0');
    read(fd_recv, buf.data(), buf.size());
    env->CallVoidMethod(send, mid_recycle);
    env->CallVoidMethod(reply, mid_recycle);

    LOGD("SystemServer reply: {}", buf);
    if (buf.find(kLSPHooker) != std::string::npos ||
        buf.find(kKr328Magic) != std::string::npos) {
        LOGE("Found system_server hook!!!");
        MarkEvilBridge(1);
    }
}

void FindModification() {
    auto maps = proc_util::MapInfo::Scan();
    for (auto& item : maps) {
        if (item.offset == 0) {
            if (item.path.ends_with("/libnullptr.so") && !CompareTextSection(item)) {
                LOGE("Fatal: libnullptr.so modified!!!");
                MarkInjection(4);
            }
            if (item.path.ends_with("/libc.so") && !CompareTextSection(item)) {
                LOGE("Fatal: libc.so modified!!!");
                MarkInjection(4);
            }
            if (item.path.ends_with("/libart.so") && !CompareTextSection(item)) {
                LOGE("libart.so modified!!!");
                MarkInjection(4);
            }
        }
    }
}

// Must be run in main thread, so we call it from native_activity_preload
void FindMntStrings() {
    // We need to get the buf address in a new process to prevent it from being covered
    // We can also hook libc@getmntent_r (plt or inline), call getmntent and get the buf address.
    constexpr const auto kMask = 0xffa13e300;
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) == -1) {
        PLOGE("pipe");
        MarkProbeUnavailable(1, "system.mount.probe.pipe");
        return;
    }
    int pid = syscall(SYS_clone, SIGCHLD, 0);
    uintptr_t value = kMask;
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        PLOGE("fork");
        MarkProbeUnavailable(1, "system.mount.probe.fork");
        return;
    } else if (pid == 0) {
        close(pipes[0]);
        FILE* f = setmntent("/proc/self/mounts", "r");
        auto buf = getmntent(f);
        if (buf != nullptr) {
            value = (uintptr_t)(++buf) ^ kMask;
        }
        endmntent(f);
        write(pipes[1], &value, sizeof(value));
        close(pipes[1]);
        _Exit(0);
    }
    close(pipes[1]);
    struct pollfd mount_probe_fd{pipes[0], POLLIN | POLLHUP | POLLERR, 0};
    int poll_result;
    do {
        poll_result = poll(&mount_probe_fd, 1, 750);
    } while (poll_result < 0 && errno == EINTR);
    ssize_t value_bytes = -1;
    if (poll_result > 0 && (mount_probe_fd.revents & (POLLIN | POLLHUP))) {
        value_bytes = read(pipes[0], &value, sizeof(value));
    }
    close(pipes[0]);
    if (value_bytes != sizeof(value)) {
        KillAndReap(pid);
        MarkProbeUnavailable(1, "system.mount.probe.timeout");
        return;
    }
    int status;
    if (!WaitPidWithTimeout(pid, &status, 500)) {
        KillAndReap(pid);
        MarkProbeUnavailable(1, "system.mount.probe.reap");
        return;
    }
    LOGD("value={:x}", value);
    value = value ^ kMask;
    LOGD("value={:x}", value);
    if (value == 0) {
        LOGE("no buf!");
        MarkProbeUnavailable(1, "system.mount.probe.buffer");
        return;
    }
    char (&mntent_strings)[1024] = *reinterpret_cast<char(*)[1024]>(value);
    std::string s;
    for (auto ch: mntent_strings) {
        if (ch >= 32 && ch < 127) {
            s += ch;
        } else {
            s += ' ';
        }
    }
    LOGD("mntent_strings: {} {}", s.size(), s);
    memcpy(mnt_strings, mntent_strings, sizeof(mnt_strings));
}

void FindFutileHide() {
    constexpr const auto SEC = 1'000'000'000l;
    constexpr const auto FUTURE_TIMESTAMP_TOLERANCE = 5 * SEC;
    constexpr static auto kMountInfo = "/proc/self/mountinfo";
    constexpr static auto kNsMnt = "/proc/self/ns/mnt";
    struct timespec start{};
    clock_gettime(CLOCK_REALTIME_COARSE, &start);
    usleep(100);
    {
        struct stat st{};
        if (fstatat(AT_FDCWD, kNsMnt, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            LOGE("err {} {}", errno, strerror(errno));
        } else {
            auto dt = (st.st_ctim.tv_sec - start.tv_sec) * SEC + (st.st_ctim.tv_nsec - start.tv_nsec);
            LOGI("time delta for ns mnt = {} stat ctime = {} start = {}", dt,
                 st.st_atim.tv_sec * SEC + st.st_atim.tv_nsec,
                 start.tv_sec * SEC + start.tv_nsec);
            // procfs timestamps describe the lifetime of the virtual entry and
            // are normally older than this call. Only a timestamp well into the
            // future is contradictory; an older ctime is not an access-timing signal.
            if (dt > FUTURE_TIMESTAMP_TOLERANCE) MarkFutileHide(1u << 2);
        }
    }
    {
        struct stat st{};
        if (stat(kMountInfo, &st) == -1) {
            LOGE("err {} {}", errno, strerror(errno));
        } else {
            auto dt = (st.st_ctim.tv_sec - start.tv_sec) * SEC + (st.st_ctim.tv_nsec - start.tv_nsec);
            LOGI("time delta for mount info = {} stat ctime = {} start = {}", dt,
                 st.st_atim.tv_sec * SEC + st.st_atim.tv_nsec,
                 start.tv_sec * SEC + start.tv_nsec);
            if (dt > FUTURE_TIMESTAMP_TOLERANCE) MarkFutileHide(1u << 2);
        }
    }
    FindMntStrings();
}
