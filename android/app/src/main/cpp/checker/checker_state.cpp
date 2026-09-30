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

pid_t ppid = 0;

bool sFoundPermissionLoophole = false;
bool sAbnormalEnvironment = false;
bool sSurroundingSuspicious = false;
bool sInconsistentMount = false;
uint8_t sPropertyAreaModified = 0;
uint8_t sPropertyItemModified = 0;
double sTransactionRate[5];
uint8_t sFoundInjection = 0;
uint8_t sEvilBridge = 0;
uint32_t sFutileHide = 0;
uint32_t sConventionalTests = 0;
uint32_t sDirtySepolicy = 0;
uint32_t sRuntimeIntegrity = 0;
uint32_t sKernelSuProbe = 0;
uint32_t sKernelSuVersion = 0;
uint32_t sKernelSuFlags = 0;
uint32_t sKernelSuUapiVersion = 0;
int32_t sKernelSuMagicErrno = 0;
bool sThroneHuntAvailable = false;
bool sThroneHuntDetected = false;
uint32_t sThroneHuntBaselineOpen = 0;
uint32_t sThroneHuntBaselineAccess = 0;
uint32_t sThroneHuntFinalOpen = 0;
uint32_t sThroneHuntFinalAccess = 0;
uint32_t sThroneHuntFinalRaw = 0;
uint32_t sThroneHuntFinalInvalid = 0;
std::string sThroneHuntDetail;
uint8_t sTeeSimulator = 0;
uint32_t sReadProc = 0;
uint8_t sAbnormalKey = 0;
uint64_t sKeyAttestationFlags = 0;
std::vector<UnavailableProbe> sUnavailableProbes;
std::unordered_set<std::string> sUnavailableProbeSet;
int mnt_check_appzygote = 0;

enum AbnormalMark : uint8_t {
    SCORE_ERROR = 0,
    SCORE_PERMISSION,
    SCORE_ABNORMAL_ENV,
    SCORE_SURROUNDING,
    SCORE_INCONSISTENT_MOUNT,
    SCORE_PROPERTY_AREA,
    SCORE_PROPERTY_ITEM,
    SCORE_INJECTION,
    SCORE_EVIL_BRIDGE,
    SCORE_FUTILE_HIDE,
    SCORE_CONVENTIONAL,
    SCORE_ABNORMAL_KEY,
    SCORE_DIRTY_SEPOLICY,
    SCORE_TEESIM_ADMIN,
    SCORE_TEESIM_CONTROL,
    SCORE_TEESIM_RS_SOTER,
    SCORE_READPROC_MOUNT,
    SCORE_READPROC_VIEW,
    SCORE_READPROC_ZN_DAEMON,
    SCORE_READPROC_LSPD,
    SCORE_READPROC_TRICKY_STORE,
    SCORE_READPROC_TEESIM_RS_DAEMON,
    SCORE_READPROC_TEESIM_RS_HOOK,
    SCORE_FRIDA_PROTOCOL,
    SCORE_FRIDA_RUNTIME,
    SCORE_NATIVE_API_OWNER,
    SCORE_KERNELSU,
};

int sAbnormalCount = 0;
uint64_t sAbnormalAppliedMask = 0;

RINLINE void MarkAbnormal(AbnormalMark mark) {
    auto bit = 1ULL << static_cast<uint8_t>(mark);
    if (sAbnormalAppliedMask & bit) return;
    sAbnormalAppliedMask |= bit;
    ++sAbnormalCount;
}

void MarkProbeUnavailable(int layer, std::string_view probe_id) {
    MarkProbeUnavailable(layer, probe_id, {}, 0, {}, {});
}

void MarkProbeUnavailable(
        int layer,
        std::string_view probe_id,
        std::string_view stage,
        int error_number,
        std::string_view detail,
        std::initializer_list<ProbeMetric> metrics) {
    std::string id(probe_id);
    if (id.empty() || layer < 0 || layer > 2) return;
    if (sUnavailableProbeSet.insert(id).second) {
        sUnavailableProbes.push_back({
                std::move(id), layer, std::string(stage), error_number,
                std::string(detail),
                std::vector<ProbeMetric>(metrics.begin(), metrics.end())});
        MarkAbnormal(SCORE_ERROR);
        return;
    }

    // Keep a later, more specific diagnostic if a generic failure for the same
    // probe was already registered. The finding itself remains de-duplicated.
    if (stage.empty() && detail.empty() && metrics.size() == 0 && error_number == 0) return;
    const auto existing = std::find_if(
            sUnavailableProbes.begin(), sUnavailableProbes.end(),
            [&](const UnavailableProbe& probe) { return probe.probeId == id; });
    if (existing == sUnavailableProbes.end()) return;
    existing->layer = layer;
    existing->stage.assign(stage);
    existing->errorNumber = error_number;
    existing->detail.assign(detail);
    existing->metrics.assign(metrics.begin(), metrics.end());
}

void MarkTeeSimulator(uint8_t finding) {
    auto fresh = static_cast<uint8_t>(finding & ~sTeeSimulator);
    sTeeSimulator |= finding;
    if (fresh & teesim_probe::ADMIN_PROTOCOL) MarkAbnormal(SCORE_TEESIM_ADMIN);
    if (fresh & teesim_probe::CONTROL_SOCKET) MarkAbnormal(SCORE_TEESIM_CONTROL);
    if (fresh & teesim_probe::RS_SOTER_PROTOCOL) MarkAbnormal(SCORE_TEESIM_RS_SOTER);
}

void MarkReadProc(uint32_t finding) {
    auto fresh = finding & ~sReadProc;
    sReadProc |= finding;
    if (fresh & READPROC_MOUNT_TRACE) MarkAbnormal(SCORE_READPROC_MOUNT);
    if (fresh & READPROC_NAMESPACE_VIEW_MISMATCH) MarkAbnormal(SCORE_READPROC_VIEW);
    if (fresh & READPROC_ZN_DAEMON) MarkAbnormal(SCORE_READPROC_ZN_DAEMON);
    if (fresh & READPROC_LSPD) MarkAbnormal(SCORE_READPROC_LSPD);
    if (fresh & READPROC_TRICKY_STORE) MarkAbnormal(SCORE_READPROC_TRICKY_STORE);
    if (fresh & READPROC_TEESIM_RS_DAEMON) MarkAbnormal(SCORE_READPROC_TEESIM_RS_DAEMON);
    if (fresh & READPROC_TEESIM_RS_HOOK) MarkAbnormal(SCORE_READPROC_TEESIM_RS_HOOK);
}

void MarkRuntimeIntegrity(uint32_t finding) {
    auto fresh = finding & ~sRuntimeIntegrity;
    sRuntimeIntegrity |= finding;
    if (fresh & runtime_probe::FRIDA_PROTOCOL) MarkAbnormal(SCORE_FRIDA_PROTOCOL);
    if (fresh & runtime_probe::FRIDA_RUNTIME_MARKER) MarkAbnormal(SCORE_FRIDA_RUNTIME);
    if (fresh & runtime_probe::NATIVE_API_OWNER_MISMATCH) {
        MarkAbnormal(SCORE_NATIVE_API_OWNER);
    }
}

void MarkKernelSuProbe(uint32_t mask) {
    const auto fresh = mask & ~sKernelSuProbe;
    sKernelSuProbe |= mask;
    if (fresh & kernelsu_probe::kDetectedMask) MarkAbnormal(SCORE_KERNELSU);
}

void MarkPermissionLoophole() {
    if (!sFoundPermissionLoophole) {
        sFoundPermissionLoophole = true;
        MarkAbnormal(SCORE_PERMISSION);
    }
}

void MarkAbnormalEnvironment() {
    if (!sAbnormalEnvironment) {
        sAbnormalEnvironment = true;
        MarkAbnormal(SCORE_ABNORMAL_ENV);
    }
}

void MarkSurroundingSuspicious() {
    if (!sSurroundingSuspicious) {
        sSurroundingSuspicious = true;
        MarkAbnormal(SCORE_SURROUNDING);
    }
}

void MarkInconsistentMount() {
    if (!sInconsistentMount) {
        sInconsistentMount = true;
        MarkAbnormal(SCORE_INCONSISTENT_MOUNT);
    }
}

void AddPropertyAreaModified() {
    if (sPropertyAreaModified < 16) ++sPropertyAreaModified;
    MarkAbnormal(SCORE_PROPERTY_AREA);
}

void AddPropertyItemModified() {
    if (sPropertyItemModified < 16) ++sPropertyItemModified;
    MarkAbnormal(SCORE_PROPERTY_ITEM);
}

void MarkInjection(uint8_t mask) {
    auto before = sFoundInjection;
    sFoundInjection |= mask;
    if (before != sFoundInjection) {
        MarkAbnormal(SCORE_INJECTION);
    }
}

void MarkEvilBridge(uint8_t mask) {
    auto before = sEvilBridge;
    sEvilBridge |= mask;
    if (before != sEvilBridge) {
        MarkAbnormal(SCORE_EVIL_BRIDGE);
    }
}

void MarkFutileHide(uint32_t mask) {
    auto before = sFutileHide;
    sFutileHide |= mask;
    if (before != sFutileHide) {
        MarkAbnormal(SCORE_FUTILE_HIDE);
    }
}

void MarkConventional(uint32_t mask) {
    auto before = sConventionalTests;
    sConventionalTests |= mask;
    if (before != sConventionalTests) {
        MarkAbnormal(SCORE_CONVENTIONAL);
    }
}

void MarkDirtySepolicy(uint32_t mask) {
    auto before = sDirtySepolicy;
    sDirtySepolicy |= mask;
    if (before != sDirtySepolicy) {
        MarkAbnormal(SCORE_DIRTY_SEPOLICY);
    }
}

void MarkAbnormalKey(uint8_t mask) {
    auto before = sAbnormalKey;
    sAbnormalKey |= mask;
    if (before != sAbnormalKey) {
        MarkAbnormal(SCORE_ABNORMAL_KEY);
    }
}

void MarkKeyAttestationFlags(uint64_t flags) {
    sKeyAttestationFlags |= flags;
    if ((flags & kDetailedKeyAttestationFindingMask) != 0) {
        MarkAbnormalKey(1);
    }
}

void msleep(int ms) {
    usleep((useconds_t)ms * 1000);
}

uint64_t MonotonicMillis() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
           static_cast<uint64_t>(ts.tv_nsec / 1'000'000ULL);
}

bool WaitPidWithTimeout(pid_t pid, int* status, int timeout_ms) {
    const uint64_t deadline = MonotonicMillis() + static_cast<uint64_t>(timeout_ms);
    for (;;) {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result == pid) return true;
        if (result < 0) {
            if (errno == EINTR) continue;
            return errno == ECHILD;
        }
        if (MonotonicMillis() >= deadline) return false;
        msleep(5);
    }
}

bool KillAndReap(pid_t pid, int timeout_ms) {
    if (pid <= 0) return true;
    if (kill(pid, SIGKILL) < 0 && errno != ESRCH) return false;
    return WaitPidWithTimeout(pid, nullptr, timeout_ms);
}

std::unordered_map<std::string, void*> sSymbolList;
uintptr_t gStackStart = 0;
uintptr_t gStackEnd = 0;
char mnt_strings[1024];
