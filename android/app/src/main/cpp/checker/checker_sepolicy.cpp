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
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/prctl.h>
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

#define _GNU_SOURCE
#include <sys/uio.h>

using namespace std::string_literals;
using namespace std::string_view_literals;

// Detection-only module. UI state and external JNI entry points remain in checker.cpp.

inline auto GetManufacturer() {
    static auto kManufacturer = []() {
        std::array<char, PROP_VALUE_MAX> prop_value{};
        ss::__system_property_get("ro.product.manufacturer", prop_value.data());
        return std::string(prop_value.data());
    }();
    return kManufacturer;
}

static bool IsKnownAndroidEmulator() {
    std::array<char, PROP_VALUE_MAX> value{};
    if (ss::__system_property_get("ro.kernel.qemu", value.data()) > 0 &&
        strcmp(value.data(), "1") == 0) {
        return true;
    }
    value.fill('\0');
    return ss::__system_property_get("ro.boot.qemu", value.data()) > 0 &&
           strcmp(value.data(), "1") == 0;
}

// Detection model adapted from LSPosed/DirtySepolicy (Apache-2.0):
// https://github.com/LSPosed/DirtySepolicy
//
// This code deliberately speaks the SELinuxFS protocol directly instead of
// using libselinux. App Zygote is allowed to query the loaded policy and check
// contexts, while an ordinary untrusted app is not. All descriptors are closed
// before preload returns so that no SELinux netlink descriptor leaks into a
// subsequently forked isolated process.
namespace dirty_sepolicy {

constexpr auto kSelinuxFs = "/sys/fs/selinux";
constexpr auto kAppZygoteContext = "u:r:app_zygote:s0";

enum class QueryResult {
    Ok,
    Invalid,
    Error,
};

enum class IoChannel {
    AbsolutePath,
    RelativePath,
};

enum class ContextResult {
    Exists,
    Missing,
    Error,
};

struct AccessVectorDecision {
    uint32_t allowed = 0;
    uint32_t decided = 0;
    uint32_t auditAllow = 0;
    uint32_t auditDeny = 0;
    uint32_t sequence = 0;
    uint32_t flags = 0;
};

struct SelinuxStatus {
    uint32_t version = 0;
    uint32_t sequence = 0;
    uint32_t enforcing = 0;
    uint32_t policyLoad = 0;
    uint32_t denyUnknown = 0;
};

static bool SameDecision(
        const AccessVectorDecision &left,
        const AccessVectorDecision &right) {
    return left.allowed == right.allowed &&
           left.decided == right.decided &&
           left.auditAllow == right.auditAllow &&
           left.auditDeny == right.auditDeny &&
           left.sequence == right.sequence &&
           left.flags == right.flags;
}

static bool SameStatus(const SelinuxStatus &left, const SelinuxStatus &right) {
    return left.version == right.version &&
           left.sequence == right.sequence &&
           left.enforcing == right.enforcing &&
           left.policyLoad == right.policyLoad &&
           left.denyUnknown == right.denyUnknown;
}

static int OpenSelinuxNode(
        const char *node,
        int flags,
        IoChannel channel,
        bool duplicate_fd) {
    int fd = -1;
    if (channel == IoChannel::RelativePath) {
        int dir_fd = open(kSelinuxFs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir_fd == -1) return -1;
        fd = openat(dir_fd, node, flags | O_CLOEXEC);
        int saved_errno = errno;
        close(dir_fd);
        errno = saved_errno;
    } else {
        std::array<char, PATH_MAX> path{};
        int length = snprintf(path.data(), path.size(), "%s/%s", kSelinuxFs, node);
        if (length <= 0 || static_cast<size_t>(length) >= path.size()) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(path.data(), flags | O_CLOEXEC);
    }

    // A duplicated descriptor is semantically identical but is absent from
    // simple userspace hook tables that only track open/openat return values.
    if (fd >= 0 && duplicate_fd) {
        int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (duplicate >= 0) {
            close(fd);
            fd = duplicate;
        }
    }
    return fd;
}

static void TrimKernelString(std::string &value) {
    while (!value.empty() &&
           (value.back() == '\0' || value.back() == '\n' || value.back() == '\r' ||
            value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
}

static bool ReadSmallFile(const char *path, std::string &value) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        LOGE("DirtySepolicy: open {} failed: {}", path, strerror(errno));
        return false;
    }

    std::array<char, 4096> buffer{};
    ssize_t size = TEMP_FAILURE_RETRY(read(fd, buffer.data(), buffer.size() - 1));
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;

    if (size < 0) {
        LOGE("DirtySepolicy: read {} failed: {}", path, strerror(errno));
        return false;
    }

    value.assign(buffer.data(), static_cast<size_t>(size));
    TrimKernelString(value);
    return true;
}

static bool ParseUint32(std::string_view text, int base, uint32_t &value) {
    if (text.empty()) return false;

    std::string copy(text);
    char *end = nullptr;
    errno = 0;
    unsigned long parsed = strtoul(copy.c_str(), &end, base);
    if (errno != 0 || end == copy.c_str() || parsed > 0xffffffffUL) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') ++end;
    if (*end != '\0') return false;

    value = static_cast<uint32_t>(parsed);
    return true;
}

static bool ReadUint32File(const char *path, uint32_t &value) {
    std::string text;
    if (!ReadSmallFile(path, text) || !ParseUint32(text, 10, value)) {
        LOGE("DirtySepolicy: invalid integer in {}", path);
        return false;
    }
    return true;
}

static bool ReadClassPermission(
        const char *class_name,
        const char *permission_name,
        uint32_t &class_id,
        uint32_t &permission_mask) {
    std::array<char, PATH_MAX> path{};
    int length = snprintf(
            path.data(), path.size(), "%s/class/%s/index", kSelinuxFs, class_name);
    if (length <= 0 || static_cast<size_t>(length) >= path.size() ||
        !ReadUint32File(path.data(), class_id)) {
        return false;
    }

    uint32_t permission_id = 0;
    length = snprintf(
            path.data(), path.size(), "%s/class/%s/perms/%s",
            kSelinuxFs, class_name, permission_name);
    if (length <= 0 || static_cast<size_t>(length) >= path.size() ||
        !ReadUint32File(path.data(), permission_id)) {
        return false;
    }
    if (permission_id == 0 || permission_id > 32) {
        LOGE("DirtySepolicy: invalid permission id {} for {}:{}",
             permission_id, class_name, permission_name);
        return false;
    }

    permission_mask = 1u << (permission_id - 1);
    return true;
}

static QueryResult QueryAccessVector(
        std::string_view source_context,
        std::string_view target_context,
        uint32_t class_id,
        AccessVectorDecision &decision,
        IoChannel channel = IoChannel::AbsolutePath,
        bool duplicate_fd = false) {
    std::array<char, PATH_MAX> request{};
    int request_size = snprintf(
            request.data(), request.size(), "%.*s %.*s %u",
            static_cast<int>(source_context.size()), source_context.data(),
            static_cast<int>(target_context.size()), target_context.data(),
            class_id);
    if (request_size <= 0 || static_cast<size_t>(request_size) >= request.size()) {
        LOGE("DirtySepolicy: access query is too long");
        return QueryResult::Error;
    }

    int fd = OpenSelinuxNode("access", O_RDWR, channel, duplicate_fd);
    if (fd == -1) {
        LOGE("DirtySepolicy: open access failed: {}", strerror(errno));
        return QueryResult::Error;
    }

    ssize_t written = TEMP_FAILURE_RETRY(write(
            fd, request.data(), static_cast<size_t>(request_size)));
    if (written != request_size) {
        int saved_errno = written < 0 ? errno : EIO;
        close(fd);
        errno = saved_errno;
        if (written < 0 && errno == EINVAL) return QueryResult::Invalid;
        LOGE("DirtySepolicy: write access query failed: {}", strerror(errno));
        return QueryResult::Error;
    }

    std::array<char, 128> response{};
    ssize_t response_size = TEMP_FAILURE_RETRY(read(fd, response.data(), response.size() - 1));
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (response_size < 0) {
        if (errno == EINVAL) return QueryResult::Invalid;
        LOGE("DirtySepolicy: read access result failed: {}", strerror(errno));
        return QueryResult::Error;
    }

    response[static_cast<size_t>(response_size)] = '\0';
    unsigned allowed = 0;
    unsigned decided = 0;
    unsigned audit_allow = 0;
    unsigned audit_deny = 0;
    unsigned sequence = 0;
    unsigned flags = 0;
    if (sscanf(response.data(), "%x %x %x %x %u %x",
               &allowed, &decided, &audit_allow, &audit_deny, &sequence, &flags) != 6) {
        LOGE("DirtySepolicy: invalid access result: {}", response.data());
        return QueryResult::Error;
    }

    decision = {
            allowed,
            decided,
            audit_allow,
            audit_deny,
            sequence,
            flags,
    };
    return QueryResult::Ok;
}

static bool CheckAccess(
        std::string_view source_context,
        std::string_view target_context,
        const char *class_name,
        const char *permission_name,
        bool &allowed,
        IoChannel channel = IoChannel::RelativePath,
        bool duplicate_fd = true,
        AccessVectorDecision *out_decision = nullptr) {
    uint32_t class_id = 0;
    uint32_t permission_mask = 0;
    if (!ReadClassPermission(class_name, permission_name, class_id, permission_mask)) {
        return false;
    }

    AccessVectorDecision decision{};
    auto query = QueryAccessVector(
            source_context, target_context, class_id, decision, channel, duplicate_fd);
    if (query == QueryResult::Invalid) {
        allowed = false;
        return true;
    }
    if (query != QueryResult::Ok) return false;

    allowed = (decision.allowed & permission_mask) == permission_mask;
    if (out_decision != nullptr) *out_decision = decision;
    return true;
}

static ContextResult ContextExists(
        std::string_view context,
        IoChannel channel = IoChannel::AbsolutePath,
        bool duplicate_fd = false) {
    int fd = OpenSelinuxNode("context", O_WRONLY, channel, duplicate_fd);
    if (fd == -1) {
        LOGE("DirtySepolicy: open context failed: {}", strerror(errno));
        return ContextResult::Error;
    }

    ssize_t written = TEMP_FAILURE_RETRY(write(fd, context.data(), context.size()));
    int saved_errno = written < 0 ? errno : EIO;
    close(fd);
    errno = saved_errno;
    if (written == static_cast<ssize_t>(context.size())) return ContextResult::Exists;
    if (written >= 0 || errno != EINVAL) {
        LOGE("DirtySepolicy: check_context failed: {}", strerror(errno));
        return ContextResult::Error;
    }

    AccessVectorDecision decision{};
    auto access_result = QueryAccessVector(
            context, context, 0, decision, channel, duplicate_fd);
    if (access_result == QueryResult::Ok) return ContextResult::Exists;
    if (access_result == QueryResult::Error) return ContextResult::Error;

    fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        LOGE("DirtySepolicy: open attr/current failed: {}", strerror(errno));
        return ContextResult::Error;
    }
    written = TEMP_FAILURE_RETRY(write(fd, context.data(), context.size()));
    saved_errno = written < 0 ? errno : EIO;
    close(fd);
    errno = saved_errno;
    if (written == static_cast<ssize_t>(context.size())) {
        LOGE("DirtySepolicy: unexpected successful setcon");
        return ContextResult::Error;
    }
    if (written < 0 && errno == EINVAL) return ContextResult::Missing;
    if (written < 0 && (errno == EPERM || errno == EACCES)) {
        // The context parsed successfully; strict SELinux then rejected the
        // dyntransition. Kernels commonly surface that AVC denial as EACCES,
        // while some vendor implementations use EPERM.
        return ContextResult::Exists;
    }

    LOGE("DirtySepolicy: setcon probe failed: {}", strerror(errno));
    return ContextResult::Error;
}

static ContextResult ContextExistsConsistently(
        std::string_view context,
        uint32_t &result) {
    auto absolute = ContextExists(context, IoChannel::AbsolutePath, false);
    auto relative = ContextExists(context, IoChannel::RelativePath, true);
    if ((absolute == ContextResult::Error) != (relative == ContextResult::Error)) {
        // Preserve the valid/raw answer, but do not silently treat a broken
        // comparison channel as a fully verified clean result.
        result |= APP_ZYGOTE_SEPOLICY_PROBE_ERROR;
        auto valid = absolute == ContextResult::Error ? relative : absolute;
        // A positive existence result remains useful. A one-channel Missing
        // result is unknown and must never support a policy-view contradiction.
        return valid == ContextResult::Exists ? ContextResult::Exists
                                              : ContextResult::Error;
    }
    if (absolute != ContextResult::Error && relative != ContextResult::Error &&
        absolute != relative) {
        result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;
        // At least one independent channel constructed the context, so retain
        // the positive signal while reporting the disagreement.
        return ContextResult::Exists;
    }
    return relative != ContextResult::Error ? relative : absolute;
}

static bool ReadFileContext(const char *path, std::string &context) {
    std::array<char, 4096> buffer{};
    // Match Os.getxattr() used by DirtySepolicy: /proc/self is a magic
    // symlink and its target process entry owns the context we need to verify.
    auto size = static_cast<ssize_t>(syscall(
            __NR_getxattr, path, "security.selinux", buffer.data(), buffer.size() - 1));
    if (size < 0) {
        LOGE("DirtySepolicy: getfilecon {} failed: {}", path, strerror(errno));
        return false;
    }
    context.assign(buffer.data(), static_cast<size_t>(size));
    TrimKernelString(context);
    return true;
}

static bool ParseStatusBytes(const void *data, size_t size, SelinuxStatus &status) {
    if (data == nullptr || size < sizeof(uint32_t) * 5) return false;
    std::array<uint32_t, 5> values{};
    memcpy(values.data(), data, sizeof(values));
    status = {
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
    };
    return true;
}

static bool ReadStatus(
        SelinuxStatus &status,
        IoChannel channel = IoChannel::AbsolutePath,
        bool duplicate_fd = false,
        bool use_pread = false) {
    int fd = OpenSelinuxNode("status", O_RDONLY, channel, duplicate_fd);
    if (fd == -1) {
        LOGE("DirtySepolicy: open status failed: {}", strerror(errno));
        return false;
    }

    std::array<uint8_t, sizeof(uint32_t) * 5> bytes{};
    size_t offset = 0;
    while (offset < bytes.size()) {
        ssize_t size = use_pread
                ? TEMP_FAILURE_RETRY(pread(
                        fd, bytes.data() + offset, bytes.size() - offset,
                        static_cast<off_t>(offset)))
                : TEMP_FAILURE_RETRY(read(fd, bytes.data() + offset, bytes.size() - offset));
        if (size <= 0) {
            int saved_errno = size == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            LOGE("DirtySepolicy: read status failed: {}", strerror(errno));
            return false;
        }
        offset += static_cast<size_t>(size);
    }
    close(fd);

    return ParseStatusBytes(bytes.data(), bytes.size(), status);
}

static bool ReadMappedStatus(SelinuxStatus &status) {
    unsigned long page_size = getauxval(AT_PAGESZ);
    if (page_size < 4096 || page_size > 65536 ||
        (page_size & (page_size - 1)) != 0) {
        return false;
    }

    int fd = OpenSelinuxNode("status", O_RDONLY, IoChannel::RelativePath, true);
    if (fd == -1) return false;
    void *mapping = mmap(
            nullptr, static_cast<size_t>(page_size), PROT_READ, MAP_SHARED, fd, 0);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (mapping == MAP_FAILED) return false;

    bool ok = false;
    auto *words = static_cast<volatile const uint32_t *>(mapping);
    for (int attempt = 0; attempt < 64; ++attempt) {
        uint32_t before = words[1];
        if ((before & 1u) != 0) continue;
        std::atomic_thread_fence(std::memory_order_acquire);
        SelinuxStatus snapshot{
                words[0], before, words[2], words[3], words[4]
        };
        std::atomic_thread_fence(std::memory_order_acquire);
        uint32_t after = words[1];
        if (before == after && (after & 1u) == 0) {
            status = snapshot;
            ok = true;
            break;
        }
    }
    munmap(mapping, static_cast<size_t>(page_size));
    return ok;
}

struct PolicyMarkers {
    bool magisk = false;
    bool kernelSu = false;
    bool apatch = false;
    bool lsposed = false;
    bool xposed = false;
    bool adbRoot = false;
};

enum class PolicyScanResult {
    Ok,
    Unavailable,
    Error,
};

static PolicyScanResult ScanPolicyMarkers(PolicyMarkers &markers) {
    int fd = OpenSelinuxNode("policy", O_RDONLY, IoChannel::RelativePath, true);
    if (fd == -1) {
        // AOSP App Zygote normally lacks kernel:security read_policy. OEMs may
        // grant it, so this is an optional enhancement and denial is expected.
        if (errno == EACCES || errno == EPERM || errno == ENOENT || errno == EBUSY) {
            return PolicyScanResult::Unavailable;
        }
        return PolicyScanResult::Error;
    }

    constexpr size_t kCarry = 64;
    constexpr size_t kChunk = 32 * 1024;
    constexpr size_t kMaxPolicyBytes = 64 * 1024 * 1024;
    std::array<char, kChunk + kCarry> buffer{};
    size_t carry = 0;
    size_t total = 0;
    bool failed = false;
    bool unavailable = false;
    for (;;) {
        ssize_t count = TEMP_FAILURE_RETRY(read(fd, buffer.data() + carry, kChunk));
        if (count < 0) {
            // SELinux may defer kernel:security read_policy authorization until
            // the first read even though open() succeeded. This is the normal
            // AOSP App Zygote outcome, not a detector failure.
            unavailable = total == 0 &&
                    (errno == EACCES || errno == EPERM || errno == ENOENT || errno == EBUSY);
            failed = !unavailable;
            break;
        }
        if (count == 0) break;
        total += static_cast<size_t>(count);
        if (total > kMaxPolicyBytes) {
            failed = true;
            errno = EFBIG;
            break;
        }

        std::string_view window(buffer.data(), carry + static_cast<size_t>(count));
        markers.magisk = markers.magisk ||
                window.find("magisk_file") != std::string_view::npos ||
                window.find("magisk_exec") != std::string_view::npos ||
                window.find("magisk_client") != std::string_view::npos;
        markers.kernelSu = markers.kernelSu ||
                window.find("ksu_file") != std::string_view::npos ||
                window.find("ksu_exec") != std::string_view::npos;
        markers.apatch = markers.apatch ||
                window.find("apatch_file") != std::string_view::npos ||
                window.find("apatch_exec") != std::string_view::npos ||
                window.find("apatch_lite") != std::string_view::npos;
        markers.lsposed = markers.lsposed ||
                window.find("lsposed_file") != std::string_view::npos;
        markers.xposed = markers.xposed ||
                window.find("xposed_data") != std::string_view::npos ||
                window.find("xposed_file") != std::string_view::npos;
        markers.adbRoot = markers.adbRoot ||
                window.find("adbroot") != std::string_view::npos;

        carry = std::min(kCarry, window.size());
        memmove(buffer.data(), window.data() + window.size() - carry, carry);
    }
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (unavailable) return PolicyScanResult::Unavailable;
    return failed ? PolicyScanResult::Error : PolicyScanResult::Ok;
}

static bool IsUserBuild(JNIEnv *env, bool &is_user) {
    jclass build_class = env->FindClass("android/os/Build");
    if (build_class == nullptr) {
        env->ExceptionClear();
        LOGE("DirtySepolicy: android.os.Build not found");
        return false;
    }

    jfieldID type_field = env->GetStaticFieldID(
            build_class, "TYPE", "Ljava/lang/String;");
    if (type_field == nullptr) {
        env->ExceptionClear();
        env->DeleteLocalRef(build_class);
        LOGE("DirtySepolicy: Build.TYPE not found");
        return false;
    }

    auto type = static_cast<jstring>(env->GetStaticObjectField(build_class, type_field));
    env->DeleteLocalRef(build_class);
    if (type == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        if (type != nullptr) env->DeleteLocalRef(type);
        LOGE("DirtySepolicy: Build.TYPE read failed");
        return false;
    }

    const char *chars = env->GetStringUTFChars(type, nullptr);
    if (chars == nullptr) {
        env->ExceptionClear();
        env->DeleteLocalRef(type);
        LOGE("DirtySepolicy: Build.TYPE conversion failed");
        return false;
    }
    is_user = strcmp(chars, "user") == 0;
    env->ReleaseStringUTFChars(type, chars);
    env->DeleteLocalRef(type);
    return true;
}

static uint32_t ProbeError(std::string_view stage) {
    LOGE("DirtySepolicy: probe failed at {}", stage);
    return APP_ZYGOTE_SEPOLICY_PROBE_ERROR;
}

struct ContextEvidence {
    bool exists = false;
    bool definitelyMissing = false;
};

template<size_t N>
static ContextEvidence ProbeContextCandidates(
        const char *const (&candidates)[N],
        std::string_view stage,
        uint32_t &result) {
    bool all_missing = true;
    for (const char *candidate : candidates) {
        auto state = ContextExistsConsistently(candidate, result);
        if (state == ContextResult::Exists) return {true, false};
        if (state == ContextResult::Error) {
            result |= ProbeError(stage);
            all_missing = false;
        }
    }
    return {false, all_missing};
}

static bool CheckEquivalentAccessChannels(
        std::string_view source_context,
        std::string_view target_context,
        const char *class_name,
        const char *permission_name,
        bool &allowed,
        bool &mismatch,
        uint32_t &sequence) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        AccessVectorDecision absolute{};
        AccessVectorDecision relative{};
        bool absolute_allowed = false;
        bool relative_allowed = false;
        if (!CheckAccess(
                source_context, target_context, class_name, permission_name,
                absolute_allowed, IoChannel::AbsolutePath, false, &absolute) ||
            !CheckAccess(
                source_context, target_context, class_name, permission_name,
                relative_allowed, IoChannel::RelativePath, true, &relative)) {
            return false;
        }
        if (absolute.sequence != relative.sequence) continue;

        mismatch = absolute_allowed != relative_allowed || !SameDecision(absolute, relative);
        allowed = relative_allowed;
        sequence = relative.sequence;
        return true;
    }

    // A policy reload between the two views is indistinguishable from a
    // channel mismatch. Report an indeterminate probe rather than a finding.
    return false;
}

struct FileAccessFingerprint {
    bool complete = true;
    std::array<bool, 4> allowed{};
};

static FileAccessFingerprint ProbeKeystoreFileAccess(
        std::string_view target_context,
        uint32_t &result) {
    constexpr std::array<const char*, 4> kPermissions = {
            "read", "map", "execute", "write"
    };
    FileAccessFingerprint fingerprint;
    for (size_t i = 0; i < kPermissions.size(); ++i) {
        bool allowed = false;
        bool mismatch = false;
        uint32_t sequence = 0;
        if (!CheckEquivalentAccessChannels(
                "u:r:keystore:s0", target_context, "file", kPermissions[i],
                allowed, mismatch, sequence)) {
            fingerprint.complete = false;
            result |= APP_ZYGOTE_SEPOLICY_PROBE_ERROR;
            continue;
        }
        if (mismatch) {
            fingerprint.complete = false;
            result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;
        } else {
            fingerprint.allowed[i] = allowed;
        }
        if (sequence == 0) result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;
    }
    return fingerprint;
}

static bool StatusChannelsAgree(SelinuxStatus &authoritative, bool &mismatch) {
    mismatch = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        SelinuxStatus absolute{};
        SelinuxStatus relative{};
        if (!ReadStatus(absolute, IoChannel::AbsolutePath, false, false) ||
            !ReadStatus(relative, IoChannel::RelativePath, true, true)) {
            return false;
        }

        // A policy update between channels is not tampering. Retry inside a
        // stable, even seqlock window before comparing their contents.
        if ((absolute.sequence & 1u) != 0 || (relative.sequence & 1u) != 0 ||
            absolute.sequence != relative.sequence) {
            continue;
        }

        authoritative = relative;
        mismatch = !SameStatus(absolute, relative);

        // mmap is an optional third view. Some vendor kernels or old releases
        // legitimately reject it, so absence is only a compatibility downgrade.
        SelinuxStatus mapped{};
        if (ReadMappedStatus(mapped)) {
            if ((mapped.sequence & 1u) != 0 || mapped.sequence != relative.sequence) continue;
            mismatch = mismatch || !SameStatus(relative, mapped);
            authoritative = mapped;
        }
        return true;
    }
    // A persistently moving/odd status page is an indeterminate probe, not a
    // policy finding. The caller reports it as unavailable and may retry later.
    return false;
}

static uint32_t Check(JNIEnv *env) {
    struct stat selinux_fs{};
    if (stat(kSelinuxFs, &selinux_fs) != 0 || !S_ISDIR(selinux_fs.st_mode)) {
        return ProbeError("SELinux disabled");
    }

    std::array<char, PATH_MAX> thread_context_path{};
    int path_size = snprintf(
            thread_context_path.data(), thread_context_path.size(),
            "/proc/self/task/%ld/attr/current", static_cast<long>(syscall(SYS_gettid)));
    if (path_size <= 0 || static_cast<size_t>(path_size) >= thread_context_path.size()) {
        return ProbeError("thread context path");
    }

    std::string context;
    if (!ReadSmallFile(thread_context_path.data(), context) ||
        !context.starts_with(kAppZygoteContext)) {
        LOGE("DirtySepolicy: unexpected context {}", context);
        return ProbeError("current context");
    }

    std::array<char, PATH_MAX> pid_context_path{};
    path_size = snprintf(
            pid_context_path.data(), pid_context_path.size(),
            "/proc/%ld/attr/current", static_cast<long>(getpid()));
    std::string pid_context;
    if (path_size <= 0 || static_cast<size_t>(path_size) >= pid_context_path.size() ||
        !ReadSmallFile(pid_context_path.data(), pid_context) || pid_context != context) {
        LOGE("DirtySepolicy: pid context mismatch: {}", pid_context);
        return ProbeError("pid context");
    }

    std::string proc_context;
    if (!ReadFileContext("/proc/self", proc_context) || proc_context != context) {
        LOGE("DirtySepolicy: /proc/self context mismatch: {}", proc_context);
        return ProbeError("proc context");
    }

    uint32_t result = 0;
    bool allowed = false;
    bool channel_mismatch = false;
    uint32_t sequence = 0;
    if (!CheckEquivalentAccessChannels(
            context, context, "process", "setcurrent",
            allowed, channel_mismatch, sequence) || !allowed) {
        return ProbeError("security:compute_av");
    }
    if (sequence == 0) result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;
    if (channel_mismatch) result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;

    if (!CheckEquivalentAccessChannels(
            context, context, "process", "execmem",
            allowed, channel_mismatch, sequence)) {
        return result | ProbeError("app_zygote execmem control");
    }
    if (!allowed) result |= APP_ZYGOTE_ACCESS_ORACLE_TAMPERED;
    if (channel_mismatch) result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;
    if (sequence == 0) result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;

    if (!CheckEquivalentAccessChannels(
            context, "u:r:kernel:s0", "security", "check_context",
            allowed, channel_mismatch, sequence) || !allowed) {
        return result | ProbeError("security:check_context");
    }
    if (channel_mismatch) result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;
    if (sequence == 0) result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;

    // All Android domains have stable self process permissions. dsp_bypass
    // scrubs the whole system_server -> system_server decision regardless of
    // class or requested permission, turning all these positive controls into
    // identical denials. Require all controls to fail before flagging it so an
    // OEM-specific omission cannot cause a false positive.
    constexpr const char *kSystemServerSelfControls[] = {
            "getattr", "getpgid", "getsched", "fork"
    };
    int self_control_successes = 0;
    int self_control_queries = 0;
    for (const char *permission : kSystemServerSelfControls) {
        bool control_allowed = false;
        if (!CheckEquivalentAccessChannels(
                "u:r:system_server:s0", "u:r:system_server:s0",
                "process", permission, control_allowed, channel_mismatch, sequence)) {
            result |= APP_ZYGOTE_SEPOLICY_PROBE_ERROR;
            continue;
        }
        ++self_control_queries;
        if (control_allowed) ++self_control_successes;
        if (channel_mismatch) result |= APP_ZYGOTE_USERSPACE_QUERY_TAMPERED;
        if (sequence == 0) result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;
    }
    if (self_control_queries >= 2 && self_control_successes == 0) {
        result |= APP_ZYGOTE_ACCESS_ORACLE_TAMPERED;
    }

    std::string enforcing;
    std::array<char, PATH_MAX> enforce_path{};
    snprintf(enforce_path.data(), enforce_path.size(), "%s/enforce", kSelinuxFs);
    uint32_t enforce_value = 0;
    if (!ReadSmallFile(enforce_path.data(), enforcing) ||
        !ParseUint32(enforcing, 10, enforce_value)) {
        result |= ProbeError("enforcing state");
    } else if (enforce_value != 1) {
        result |= APP_ZYGOTE_SELINUX_PERMISSIVE;
    }

    if (!CheckAccess(
            "u:r:system_server:s0", "u:r:system_server:s0",
            "process", "execmem", allowed)) {
        result |= ProbeError("system_server execmem");
    } else if (allowed && !IsKnownAndroidEmulator()) {
        result |= APP_ZYGOTE_SYSTEM_SERVER_EXECMEM;
    }

    // TEESimulator-RS grants keystore wildcard file access to both adb and
    // shell data. Require a multi-permission signature on two independent
    // target types so a single OEM-specific allow rule cannot trigger it.
    auto adb_data_access = ProbeKeystoreFileAccess("u:object_r:adb_data_file:s0", result);
    auto shell_data_access = ProbeKeystoreFileAccess("u:object_r:shell_data_file:s0", result);
    const bool adb_core_allowed = adb_data_access.allowed[0] &&
                                  adb_data_access.allowed[1] &&
                                  adb_data_access.allowed[2];
    const auto shell_allowed_count = std::count(
            shell_data_access.allowed.begin(), shell_data_access.allowed.end(), true);
    if (adb_data_access.complete && shell_data_access.complete && adb_core_allowed &&
        (adb_data_access.allowed[3] || shell_allowed_count >= 2)) {
        result |= APP_ZYGOTE_TEESIM_KEYSTORE_POLICY;
        LOGE("DirtySepolicy: TEESimulator-RS keystore file-access fingerprint matched");
    }

    bool is_user_build = false;
    if (!IsUserBuild(env, is_user_build)) {
        result |= ProbeError("build type");
    } else if (is_user_build) {
        if (!CheckAccess(
                "u:r:shell:s0", "u:r:su:s0", "process", "transition", allowed)) {
            result |= ProbeError("AOSP su");
        } else if (allowed) {
            result |= APP_ZYGOTE_AOSP_SU;
        }
    }

    constexpr const char *kAdbRootContexts[] = {"u:r:adbroot:s0"};
    auto adb_context = ProbeContextCandidates(kAdbRootContexts, "adb_root context", result);
    if (adb_context.exists) result |= APP_ZYGOTE_ADB_ROOT;

    constexpr const char *kMagiskContexts[] = {
            "u:r:magisk:s0",
            "u:object_r:magisk_file:s0",
            "u:r:magisk_client:s0",
            "u:object_r:magisk_exec:s0",
    };
    auto magisk_context = ProbeContextCandidates(kMagiskContexts, "Magisk contexts", result);
    bool found = magisk_context.exists;
    if (!found) {
        allowed = false;
        if (!CheckAccess(
                "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0",
                "filesystem", "associate", allowed)) {
            result |= ProbeError("Magisk associate rule");
        } else {
            found = allowed;
        }
    }
    if (!found) {
        allowed = false;
        if (!CheckAccess(
                "u:r:kernel:s0", "u:object_r:tmpfs:s0",
                "fifo_file", "open", allowed)) {
            result |= ProbeError("Magisk fifo rule");
        } else {
            found = allowed;
        }
    }
    if (found) result |= APP_ZYGOTE_MAGISK_POLICY;

    constexpr const char *kKernelSuContexts[] = {
            "u:r:ksu:s0",
            "u:object_r:ksu_file:s0",
            "u:object_r:ksu_exec:s0",
    };
    auto ksu_context = ProbeContextCandidates(kKernelSuContexts, "KernelSU contexts", result);
    found = ksu_context.exists;
    if (!found) {
        allowed = false;
        if (!CheckAccess(
                "u:r:kernel:s0", "u:object_r:adb_data_file:s0",
                "file", "read", allowed)) {
            result |= ProbeError("KernelSU read rule");
        } else {
            found = allowed;
        }
    }
    if (found) result |= APP_ZYGOTE_KERNEL_SU_POLICY;

    // APatch uses its own domains on current releases. Keep these probes
    // separate so the UI can identify the policy family without conflating it
    // with KernelSU.
    constexpr const char *kAPatchContexts[] = {
            "u:r:apatch:s0",
            "u:r:apatch_lite:s0",
            "u:object_r:apatch_exec:s0",
            "u:object_r:apatch_file:s0",
    };
    auto apatch_context = ProbeContextCandidates(kAPatchContexts, "APatch contexts", result);
    found = apatch_context.exists;
    if (found) result |= APP_ZYGOTE_APATCH_POLICY;

    constexpr const char *kLSPosedContexts[] = {"u:object_r:lsposed_file:s0"};
    auto lsposed_context = ProbeContextCandidates(kLSPosedContexts, "LSPosed contexts", result);
    found = lsposed_context.exists;
    if (!found) {
        allowed = false;
        if (!CheckAccess(
                "u:r:system_server:s0", "u:object_r:apk_data_file:s0",
                "file", "execute", allowed)) {
            result |= ProbeError("LSPosed execute rule");
        } else {
            found = allowed;
        }
    }
    if (found) result |= APP_ZYGOTE_LSPOSED_POLICY;

    constexpr const char *kXposedContexts[] = {
            "u:object_r:xposed_data:s0",
            "u:object_r:xposed_file:s0",
    };
    auto xposed_context = ProbeContextCandidates(kXposedContexts, "Xposed contexts", result);
    found = xposed_context.exists;
    if (!found) {
        allowed = false;
        if (!CheckAccess(
                "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0",
                "file", "execute_no_trans", allowed)) {
            result |= ProbeError("Xposed execute_no_trans rule");
        } else {
            found = allowed;
        }
    }
    if (found) result |= APP_ZYGOTE_XPOSED_POLICY;

    allowed = false;
    if (!CheckAccess(
            "u:r:zygote:s0", "u:object_r:adb_data_file:s0",
            "dir", "search", allowed)) {
        result |= ProbeError("ZygiskNext search rule");
    } else if (allowed) {
        result |= APP_ZYGOTE_ZYGISK_NEXT_POLICY;
    }

    PolicyMarkers policy_markers{};
    auto policy_scan = ScanPolicyMarkers(policy_markers);
    if (policy_scan == PolicyScanResult::Error) {
        LOGE("DirtySepolicy: optional policy scan failed: {}", strerror(errno));
    } else if (policy_scan == PolicyScanResult::Ok) {
        if (policy_markers.magisk) result |= APP_ZYGOTE_MAGISK_POLICY;
        if (policy_markers.kernelSu) result |= APP_ZYGOTE_KERNEL_SU_POLICY;
        if (policy_markers.apatch) result |= APP_ZYGOTE_APATCH_POLICY;
        if (policy_markers.lsposed) result |= APP_ZYGOTE_LSPOSED_POLICY;
        if (policy_markers.xposed) result |= APP_ZYGOTE_XPOSED_POLICY;
        if (policy_markers.adbRoot) result |= APP_ZYGOTE_ADB_ROOT;
        // Only call the two views contradictory when every matching context
        // query explicitly returned EINVAL. A probe error is unknown, not proof
        // that a userspace or kernel hook hid the type.
        if ((policy_markers.magisk && magisk_context.definitelyMissing) ||
            (policy_markers.kernelSu && ksu_context.definitelyMissing) ||
            (policy_markers.apatch && apatch_context.definitelyMissing) ||
            (policy_markers.lsposed && lsposed_context.definitelyMissing) ||
            (policy_markers.xposed && xposed_context.definitelyMissing) ||
            (policy_markers.adbRoot && adb_context.definitelyMissing)) {
            result |= APP_ZYGOTE_POLICY_VIEW_TAMPERED;
        }
    }

    SelinuxStatus status{};
    AccessVectorDecision decision{};
    bool status_mismatch = false;
    bool status_window_stable = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        SelinuxStatus before{};
        SelinuxStatus after{};
        bool before_mismatch = false;
        bool after_mismatch = false;
        if (!StatusChannelsAgree(before, before_mismatch)) {
            return result | ProbeError("status before AVD");
        }
        if (QueryAccessVector(
                "u:r:untrusted_app:s0", "u:r:untrusted_app:s0", 0, decision,
                IoChannel::RelativePath, true) != QueryResult::Ok) {
            return result | ProbeError("AVD sequence");
        }
        if (!StatusChannelsAgree(after, after_mismatch)) {
            return result | ProbeError("status after AVD");
        }
        status_mismatch = status_mismatch || before_mismatch || after_mismatch;
        if (!SameStatus(before, after)) continue;
        status = after;
        status_window_stable = true;
        break;
    }
    if (!status_window_stable) {
        return result | ProbeError("unstable status/AVD window");
    }
    if (status_mismatch) result |= APP_ZYGOTE_STATUS_CHANNEL_TAMPERED;
    if (status.version != 1) {
        LOGE("DirtySepolicy: unknown status version {}", status.version);
        return result | ProbeError("status version");
    }
    if (status.enforcing != 1) result |= APP_ZYGOTE_STATUS_NOT_ENFORCING;
    if (status.denyUnknown != 1) result |= APP_ZYGOTE_DENY_UNKNOWN_DISABLED;

    // Do not predict exact values from uname; Android vendors backport status
    // changes and can legitimately load policy additional times during boot.
    if (decision.sequence == 0) {
        result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;
    }
    if (status.policyLoad > 0 && decision.sequence != status.policyLoad) {
        result |= APP_ZYGOTE_AVD_SEQUENCE_ANOMALY;
    }

    LOGI("DirtySepolicy: result={:#x} sequence={} policyload={} avd_sequence={}",
         result, status.sequence, status.policyLoad, decision.sequence);
    return result | APP_ZYGOTE_CHECK_COMPLETED;
}

} // namespace dirty_sepolicy

uint32_t CheckDirtySepolicy(JNIEnv* env) {
    return dirty_sepolicy::Check(env);
}

void FindAppZygoteDetection(JNIEnv *env, jobject context) {
    if (GetAndroidApiLevel() < 29) return;
    auto manufacturer = GetManufacturer();
    auto my_class = env->FindClass("com/lingqing/trustattestor/AppZygoteProbe");
    if (my_class == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        mnt_check_appzygote = APP_ZYGOTE_RESULT_UNAVAILABLE;
        MarkProbeUnavailable(1, "system.app_zygote.service");
        return;
    }
    auto my_method = env->GetStaticMethodID(my_class, "awaitResult", "(Landroid/content/Context;)I");
    if (my_method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(my_class);
        mnt_check_appzygote = APP_ZYGOTE_RESULT_UNAVAILABLE;
        MarkProbeUnavailable(1, "system.app_zygote.interface");
        return;
    }
    jint check = env->CallStaticIntMethod(my_class, my_method, context);
    env->DeleteLocalRef(my_class);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        mnt_check_appzygote = APP_ZYGOTE_RESULT_UNAVAILABLE;
        MarkProbeUnavailable(1, "system.app_zygote.call");
        return;
    }

    auto flags = static_cast<uint32_t>(check);
    if ((flags & APP_ZYGOTE_CHECK_COMPLETED) == 0) {
        flags |= APP_ZYGOTE_RESULT_UNAVAILABLE;
        MarkProbeUnavailable(1, "system.app_zygote.incomplete");
    }
    if ((flags & APP_ZYGOTE_ATTR_TIME_ANOMALY) &&
        manufacturer != "vivo" && manufacturer != "VIVO") {
        MarkFutileHide(1u << 2);
    }
    if (flags & APP_ZYGOTE_TMPFS_PERMISSION) MarkPermissionLoophole();
    if (flags & APP_ZYGOTE_RESULT_UNAVAILABLE) {
        MarkProbeUnavailable(1, "system.app_zygote.process");
    }
    if (flags & APP_ZYGOTE_SEPOLICY_PROBE_ERROR) {
        MarkProbeUnavailable(1, "system.app_zygote.sepolicy");
    }
    MarkDirtySepolicy(flags & kDirtySepolicyFindingMask);
    mnt_check_appzygote = static_cast<int>(flags & ~APP_ZYGOTE_CHECK_COMPLETED);
}
