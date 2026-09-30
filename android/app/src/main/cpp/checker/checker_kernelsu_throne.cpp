#include "checker_kernelsu_throne.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <string_view>
#include <sys/inotify.h>
#include <unistd.h>

#include "checker_internal.h"
#include "logging.h"

namespace {

constexpr uint32_t kWatchInstalled = 1u << 0;
constexpr uint32_t kWatchAddDenied = 1u << 1;
constexpr uint32_t kWatchInvalid = 1u << 2;
constexpr uint32_t kWatchOverflow = 1u << 3;
constexpr uint32_t kWatchGone = 1u << 4;

int gInotifyFd = -1;
int gWatchDescriptor = -1;
uint32_t gWatchState = 0;
int gWatchErrno = 0;
bool gWatchSupported = true;
std::string gPackageDirectory;
std::string gWatchStage = "not_initialized";
std::string gWatchDetail;

struct EventCounts {
    uint32_t directoryOpen = 0;
    uint32_t directoryAccess = 0;
    uint32_t namedNoise = 0;
    uint32_t raw = 0;
    uint32_t invalid = 0;
};

EventCounts gLastDrain;

enum class EventKind {
    DirectorySelf,
    NamedChildNoise,
    QueueOverflow,
    WatchIgnored,
    WrongWatch,
};

constexpr EventKind ClassifyEvent(
        int expectedWatchDescriptor,
        int eventWatchDescriptor,
        uint32_t mask,
        uint32_t nameLength) {
    if ((mask & IN_Q_OVERFLOW) != 0) return EventKind::QueueOverflow;
    if ((mask & IN_IGNORED) != 0) return EventKind::WatchIgnored;
    if (eventWatchDescriptor != expectedWatchDescriptor) return EventKind::WrongWatch;
    return nameLength == 0 ? EventKind::DirectorySelf : EventKind::NamedChildNoise;
}

constexpr bool IsCompleteEventRecord(size_t bytesRemaining, uint32_t nameLength) {
    return bytesRemaining >= sizeof(inotify_event) &&
           nameLength <= bytesRemaining - sizeof(inotify_event);
}

static_assert(ClassifyEvent(7, 7, IN_OPEN, 8) == EventKind::NamedChildNoise);
static_assert(ClassifyEvent(7, 7, IN_ACCESS, 0) == EventKind::DirectorySelf);
static_assert(ClassifyEvent(7, -1, IN_Q_OVERFLOW, 0) == EventKind::QueueOverflow);
static_assert(ClassifyEvent(7, 7, IN_IGNORED, 0) == EventKind::WatchIgnored);
static_assert(ClassifyEvent(7, 8, IN_OPEN, 0) == EventKind::WrongWatch);
static_assert(!IsCompleteEventRecord(sizeof(inotify_event) + 3, 4));

std::string Escape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (char ch : value) {
        if (ch == '\\') out += "\\\\";
        else if (ch == '\n') out += "\\n";
        else if (ch == '\r') out += "\\r";
        else if (ch == '\t') out += "\\t";
        else out.push_back(ch);
    }
    return out;
}

enum class PackagePathStatus {
    Supported,
    Unsupported,
    Invalid,
};

struct PackageDirectoryResult {
    PackagePathStatus status = PackagePathStatus::Invalid;
    std::string directory;
    std::string detail;
};

bool HasUnsafePathComponent(std::string_view path) {
    size_t start = 0;
    while (start < path.size()) {
        const size_t end = path.find('/', start);
        const auto component = path.substr(
                start, end == std::string_view::npos ? path.size() - start : end - start);
        if (component == "." || component == "..") return true;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return false;
}

bool IsSupportedInstalledApkPath(std::string_view source) {
    if (source.starts_with("/data/app/") ||
        source.starts_with("/data/app-ephemeral/")) {
        return true;
    }

    // Adoptable-storage APKs use /mnt/expand/<volume UUID>/app/... .
    constexpr std::string_view kExpandPrefix = "/mnt/expand/";
    if (!source.starts_with(kExpandPrefix)) return false;
    const size_t volumeEnd = source.find('/', kExpandPrefix.size());
    if (volumeEnd == std::string_view::npos || volumeEnd == kExpandPrefix.size()) return false;
    return source.substr(volumeEnd).starts_with("/app/");
}

bool IsInstallationRoot(std::string_view parent) {
    if (parent == "/data/app" || parent == "/data/app-ephemeral") return true;
    constexpr std::string_view kExpandPrefix = "/mnt/expand/";
    if (!parent.starts_with(kExpandPrefix)) return false;
    const size_t volumeEnd = parent.find('/', kExpandPrefix.size());
    return volumeEnd != std::string_view::npos && parent.substr(volumeEnd) == "/app";
}

PackageDirectoryResult PackageDirectory(std::string_view source) {
    if (source.empty()) {
        return {PackagePathStatus::Invalid, {}, "sourceDir is empty"};
    }
    if (source.front() != '/' || source.back() == '/' || HasUnsafePathComponent(source)) {
        return {PackagePathStatus::Invalid, {}, "sourceDir is not a safe absolute APK path"};
    }
    if (!source.ends_with(".apk")) {
        return {PackagePathStatus::Invalid, {}, "sourceDir does not name an APK"};
    }
    if (!IsSupportedInstalledApkPath(source)) {
        return {PackagePathStatus::Unsupported, {},
                "sourceDir is outside supported installed-app roots"};
    }
    const auto slash = source.find_last_of('/');
    if (slash == std::string_view::npos || slash == 0) {
        return {PackagePathStatus::Invalid, {}, "sourceDir has no package directory"};
    }
    std::string parent(source.substr(0, slash));
    if (IsInstallationRoot(parent)) {
        return {PackagePathStatus::Invalid, {}, "refusing to watch an installation root"};
    }
    return {PackagePathStatus::Supported, std::move(parent), {}};
}

void CloseWatch() {
    if (gInotifyFd >= 0) close(gInotifyFd);
    gInotifyFd = -1;
    gWatchDescriptor = -1;
    gWatchState = 0;
    gWatchStage = "closed";
}

std::string Encode(const EventCounts* counts) {
    std::string out;
    out.reserve(256);
    out += "WATCH_SUPPORTED=";
    out += gWatchSupported ? "1\n" : "0\n";
    out += "WATCH_INSTALLED=";
    out += (gWatchState & kWatchInstalled) ? "1\n" : "0\n";
    out += "WATCH_ADD_DENIED=";
    out += (gWatchState & kWatchAddDenied) ? "1\n" : "0\n";
    out += "WATCH_INVALID=";
    out += (gWatchState & kWatchInvalid) ? "1\n" : "0\n";
    out += "WATCH_OVERFLOW=";
    out += (gWatchState & kWatchOverflow) ? "1\n" : "0\n";
    out += "WATCH_GONE=";
    out += (gWatchState & kWatchGone) ? "1\n" : "0\n";
    out += "WATCH_DESCRIPTOR=" + std::to_string(gWatchDescriptor) + "\n";
    out += "WATCH_ERRNO=" + std::to_string(gWatchErrno) + "\n";
    out += "WATCH_PACKAGE_DIR=" + Escape(gPackageDirectory) + "\n";
    out += "WATCH_STAGE=" + Escape(gWatchStage) + "\n";
    out += "WATCH_DETAIL=" + Escape(gWatchDetail) + "\n";
    if (counts != nullptr) {
        out += "EVENT_DIRECTORY_OPEN=" + std::to_string(counts->directoryOpen) + "\n";
        out += "EVENT_DIRECTORY_ACCESS=" + std::to_string(counts->directoryAccess) + "\n";
        out += "EVENT_NAMED_NOISE=" + std::to_string(counts->namedNoise) + "\n";
        out += "EVENT_RAW=" + std::to_string(counts->raw) + "\n";
        out += "EVENT_INVALID=" + std::to_string(counts->invalid) + "\n";
    }
    return out;
}

std::string JStringToString(JNIEnv* env, jstring value) {
    if (env == nullptr || value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

EventCounts DrainEvents() {
    EventCounts result;
    if (gInotifyFd < 0 || gWatchDescriptor < 0) {
        gWatchState |= kWatchInvalid | kWatchGone;
        gWatchStage = "drain";
        gWatchDetail = "inotify watch is no longer installed";
        gWatchErrno = EBADF;
        return result;
    }

    alignas(inotify_event) char buffer[16 * 1024];
    for (;;) {
        const ssize_t bytes = read(gInotifyFd, buffer, sizeof(buffer));
        if (bytes < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            gWatchErrno = errno;
            gWatchState |= kWatchInvalid;
            if (errno == EBADF || errno == EINVAL) gWatchState |= kWatchGone;
            gWatchStage = "drain";
            gWatchDetail = "inotify read failed";
            break;
        }
        if (bytes == 0) break;
        size_t offset = 0;
        bool truncatedRecord = false;
        while (offset + sizeof(inotify_event) <= static_cast<size_t>(bytes)) {
            const auto* event = reinterpret_cast<const inotify_event*>(buffer + offset);
            const size_t remaining = static_cast<size_t>(bytes) - offset;
            if (!IsCompleteEventRecord(remaining, event->len)) {
                ++result.invalid;
                gWatchState |= kWatchInvalid;
                gWatchStage = "drain";
                gWatchDetail = "truncated inotify event record";
                truncatedRecord = true;
                break;
            }
            const size_t recordSize = sizeof(inotify_event) + event->len;
            ++result.raw;
            switch (ClassifyEvent(
                    gWatchDescriptor, event->wd, event->mask, event->len)) {
                case EventKind::QueueOverflow:
                    ++result.invalid;
                    gWatchState |= kWatchOverflow;
                    gWatchStage = "drain";
                    gWatchDetail = "inotify event queue overflowed";
                    break;
                case EventKind::WatchIgnored:
                    ++result.invalid;
                    gWatchState |= kWatchInvalid;
                    gWatchState |= kWatchGone;
                    gWatchDescriptor = -1;
                    gWatchStage = "drain";
                    gWatchDetail = "inotify watch was removed";
                    break;
                case EventKind::WrongWatch:
                    ++result.invalid;
                    gWatchState |= kWatchInvalid;
                    gWatchStage = "drain";
                    gWatchDetail = "inotify event used an unexpected watch descriptor";
                    break;
                case EventKind::DirectorySelf:
                    // KernelSU opens each package directory while traversing /data/app.
                    // A normal app activity does not open the watched package directory itself.
                    if (event->mask & IN_OPEN) ++result.directoryOpen;
                    if (event->mask & IN_ACCESS) ++result.directoryAccess;
                    break;
                case EventKind::NamedChildNoise:
                    // File and child-directory events are expected background noise. App
                    // Zygote startup, ART and PackageManager can all touch base.apk, split
                    // APKs or oat entries. Only opening/accessing the watched directory itself
                    // is the throne-hunt signal, so retain these events for diagnostics without
                    // making the round unavailable.
                    ++result.namedNoise;
                    break;
            }
            offset += recordSize;
        }
        if (offset != static_cast<size_t>(bytes) && !truncatedRecord) {
            ++result.invalid;
            gWatchState |= kWatchInvalid;
            gWatchStage = "drain";
            gWatchDetail = "trailing bytes after inotify event records";
        }
    }
    return result;
}

bool ParseBool(std::string_view value) {
    return value == "1" || value == "true" || value == "TRUE";
}

uint32_t ParseUint(std::string_view value) {
    if (value.empty()) return 0;
    char* end = nullptr;
    errno = 0;
    const std::string copy(value);
    const unsigned long parsed = std::strtoul(copy.c_str(), &end, 10);
    if (errno != 0 || end == copy.c_str() || *end != '\0') return 0;
    return parsed > UINT32_MAX ? 0 : static_cast<uint32_t>(parsed);
}

std::string RoundDiagnostic(
        std::string_view stage,
        std::string_view detail,
        uint32_t baselineNamedNoise = 0,
        uint32_t finalNamedNoise = 0) {
    std::string diagnostic = "stage=";
    diagnostic.append(stage.empty() ? "round" : stage);
    diagnostic += "; detail=";
    diagnostic.append(detail.empty() ? "no detail returned" : detail);
    diagnostic += "; baselineNamedNoise=" + std::to_string(baselineNamedNoise);
    diagnostic += "; finalNamedNoise=" + std::to_string(finalNamedNoise);
    return diagnostic;
}

std::string_view NormalizeUnavailableStage(std::string_view stage) {
    if (stage == "carrier_bind" || stage == "baseline" || stage == "stimulus" ||
        stage == "final_drain" || stage == "payload") {
        return stage;
    }
    if (stage == "setup" || stage == "watch_setup" || stage == "path" ||
        stage == "inotify_init" || stage == "inotify_add_watch" ||
        stage == "ready" || stage == "drain") {
        return "watch_setup";
    }
    return "payload";
}

void MarkThroneHuntUnavailable(
        std::string_view stage,
        int errorNumber,
        std::string_view detail) {
    const auto normalizedStage = NormalizeUnavailableStage(stage);
    sThroneHuntAvailable = false;
    sThroneHuntDetected = false;
    sThroneHuntDetail = RoundDiagnostic(normalizedStage, detail);
    // This is an opportunistic positive-only sampler, not a completeness gate:
    // even a successful zero-event round cannot exclude an already-registered
    // KernelSU Manager. Preserve the failure in logs without turning an otherwise
    // healthy device scan into UNAVAILABLE.
    LOGW("KernelSU manager-recovery observation unavailable: stage={} errno={} detail={}",
         normalizedStage, errorNumber, sThroneHuntDetail);
}

void SetThroneHuntUnsupported(std::string_view stage, std::string_view detail) {
    sThroneHuntAvailable = false;
    sThroneHuntDetected = false;
    sThroneHuntDetail = RoundDiagnostic(stage, detail);
    LOGI("KernelSU throne-hunt not supported: {}", sThroneHuntDetail);
}

void ApplyRoundPayload(std::string_view payload) {
    ResetThroneHuntEvidence();
    bool roundSupported = true;
    bool roundAvailable = false;
    bool stimulus = false;
    bool readback = false;
    uint32_t baselineOpen = 0;
    uint32_t baselineAccess = 0;
    uint32_t baselineNamedNoise = 0;
    uint32_t baselineInvalid = 0;
    uint32_t finalOpen = 0;
    uint32_t finalAccess = 0;
    uint32_t finalNamedNoise = 0;
    uint32_t finalRaw = 0;
    uint32_t finalInvalid = 0;
    int roundErrno = 0;
    std::string stage = "round";
    std::string detail;
    size_t start = 0;
    while (start < payload.size()) {
        size_t end = payload.find('\n', start);
        if (end == std::string_view::npos) end = payload.size();
        const auto line = payload.substr(start, end - start);
        const size_t split = line.find('=');
        if (split != std::string_view::npos) {
            const auto key = line.substr(0, split);
            const auto value = line.substr(split + 1);
            if (key == "ROUND_SUPPORTED" || key == "ROUND_APPLICABLE") {
                roundSupported = ParseBool(value);
            }
            else if (key == "ROUND_AVAILABLE") roundAvailable = ParseBool(value);
            else if (key == "STIMULUS") stimulus = ParseBool(value);
            else if (key == "READBACK") readback = ParseBool(value);
            else if (key == "BASELINE_OPEN") baselineOpen = ParseUint(value);
            else if (key == "BASELINE_ACCESS") baselineAccess = ParseUint(value);
            else if (key == "BASELINE_NAMED_NOISE") baselineNamedNoise = ParseUint(value);
            else if (key == "BASELINE_INVALID") baselineInvalid = ParseUint(value);
            else if (key == "FINAL_OPEN") finalOpen = ParseUint(value);
            else if (key == "FINAL_ACCESS") finalAccess = ParseUint(value);
            else if (key == "FINAL_NAMED_NOISE") finalNamedNoise = ParseUint(value);
            else if (key == "FINAL_RAW") finalRaw = ParseUint(value);
            else if (key == "FINAL_INVALID") finalInvalid = ParseUint(value);
            else if (key == "ERRNO" || key == "ROUND_ERRNO" || key == "WATCH_ERRNO") {
                roundErrno = static_cast<int>(ParseUint(value));
            }
            else if (key == "STAGE") stage.assign(value);
            else if (key == "DETAIL") detail.assign(value);
        }
        start = end + (end < payload.size() ? 1 : 0);
    }

    sThroneHuntBaselineOpen = baselineOpen;
    sThroneHuntBaselineAccess = baselineAccess;
    sThroneHuntFinalOpen = finalOpen;
    sThroneHuntFinalAccess = finalAccess;
    sThroneHuntFinalRaw = finalRaw;
    sThroneHuntFinalInvalid = finalInvalid;
    sThroneHuntDetail = RoundDiagnostic(
            stage, detail, baselineNamedNoise, finalNamedNoise);

    if (!roundSupported) {
        SetThroneHuntUnsupported(stage, detail);
        return;
    }

    // A round is only complete when the PackageManager state change was both
    // applied and read back. Never let a truncated or partially forged payload
    // turn an unexecuted stimulus into a usable observation.
    //
    // This sampler is deliberately positive-only: current KernelSU scans package
    // directories while recovering an absent/stale Manager identity, but may skip
    // that traversal once its Manager UID is already valid. Therefore zero matching
    // events are neutral and are never emitted as evidence that KernelSU is absent.
    sThroneHuntAvailable = roundAvailable && stimulus && readback &&
            baselineInvalid == 0 && finalInvalid == 0;
    sThroneHuntDetected = sThroneHuntAvailable &&
            (finalOpen > 0 || finalAccess > 0);

    if (!sThroneHuntAvailable) {
        LOGW("KernelSU manager-recovery observation unavailable: stage={} errno={} "
             "baselineOpen={} baselineAccess={} baselineNamedNoise={} "
             "baselineInvalid={} finalOpen={} finalAccess={} finalNamedNoise={} "
             "finalRaw={} finalInvalid={} detail={}",
             NormalizeUnavailableStage(stage), roundErrno,
             baselineOpen, baselineAccess, baselineNamedNoise, baselineInvalid,
             finalOpen, finalAccess, finalNamedNoise, finalRaw, finalInvalid,
             sThroneHuntDetail);
    } else {
        LOGI("KernelSU manager-recovery observation complete: detected={} baselineNoise={} finalNoise={}",
             sThroneHuntDetected, baselineNamedNoise, finalNamedNoise);
    }
}

}  // namespace

std::string InstallThroneHuntWatch(JNIEnv* env, jstring source_dir) {
    const auto package = PackageDirectory(JStringToString(env, source_dir));
    if (package.status != PackagePathStatus::Supported) {
        CloseWatch();
        gWatchSupported = package.status == PackagePathStatus::Invalid;
        gPackageDirectory.clear();
        gWatchStage = "path";
        gWatchDetail = package.detail;
        if (package.status == PackagePathStatus::Unsupported) {
            gWatchErrno = 0;
            LOGI("KernelSU throne-hunt unsupported installation path: {}", gWatchDetail);
            return Encode(nullptr);
        }
        gWatchState = kWatchInvalid;
        gWatchErrno = EINVAL;
        LOGW("KernelSU throne-hunt invalid installation path: {}", gWatchDetail);
        return Encode(nullptr);
    }
    gWatchSupported = true;
    if (gInotifyFd >= 0 && gPackageDirectory == package.directory &&
        (gWatchState & (kWatchInstalled | kWatchGone)) == kWatchInstalled &&
        fcntl(gInotifyFd, F_GETFD) >= 0) {
        return Encode(nullptr);
    }
    CloseWatch();
    gWatchSupported = true;
    gPackageDirectory = package.directory;
    gWatchErrno = 0;
    gWatchDetail.clear();
    gWatchStage = "inotify_init";
    gInotifyFd = inotify_init1(IN_NONBLOCK);
    if (gInotifyFd < 0) {
        gWatchErrno = errno;
        gWatchDetail = "inotify_init1 failed";
        gWatchState = kWatchInvalid;
        return Encode(nullptr);
    }
    gWatchStage = "inotify_add_watch";
    gWatchDescriptor = inotify_add_watch(gInotifyFd, gPackageDirectory.c_str(), IN_OPEN | IN_ACCESS);
    if (gWatchDescriptor < 0) {
        gWatchErrno = errno;
        gWatchDetail = "inotify_add_watch failed";
        gWatchState = kWatchAddDenied;
        close(gInotifyFd);
        gInotifyFd = -1;
        return Encode(nullptr);
    }
    gWatchState = kWatchInstalled;
    gWatchStage = "ready";
    gWatchDetail = "watch installed on package directory";
    LOGI("KernelSU throne-hunt watch installed: {} fd={} wd={}",
         gPackageDirectory, gInotifyFd, gWatchDescriptor);
    return Encode(nullptr);
}

std::string ThroneHuntWatchState() {
    // Deliberately do not read the inotify stream here. The baseline drain is a
    // separate transaction immediately before the PackageManager stimulus.
    return Encode(nullptr);
}

std::string ThroneHuntWatchDrain() {
    gLastDrain = DrainEvents();
    return Encode(&gLastDrain);
}

std::string ThroneHuntWatchReset() {
    EventCounts discarded;
    if ((gWatchState & kWatchInstalled) != 0 &&
        (gWatchState & kWatchGone) == 0 &&
        gInotifyFd >= 0 && gWatchDescriptor >= 0) {
        discarded = DrainEvents();
        if ((gWatchState & kWatchGone) == 0 &&
            gInotifyFd >= 0 && gWatchDescriptor >= 0) {
            // The round has already captured its result. Clear recoverable queue overflow,
            // malformed-record and wrong-wd state only after draining residual events so a
            // transient failure cannot poison a later scan in a reused carrier process.
            gWatchState &= ~(kWatchInvalid | kWatchOverflow);
            gWatchErrno = 0;
            gWatchStage = "ready";
            gWatchDetail = "watch reset after round; discardedRaw=" +
                    std::to_string(discarded.raw) + "; discardedNamedNoise=" +
                    std::to_string(discarded.namedNoise);
        }
    }
    gLastDrain = {};
    return Encode(&discarded);
}

void ResetThroneHuntEvidence() {
    sThroneHuntDetected = false;
    sThroneHuntAvailable = false;
    sThroneHuntBaselineOpen = 0;
    sThroneHuntBaselineAccess = 0;
    sThroneHuntFinalOpen = 0;
    sThroneHuntFinalAccess = 0;
    sThroneHuntFinalRaw = 0;
    sThroneHuntFinalInvalid = 0;
    sThroneHuntDetail.clear();
}

void FindThroneHuntDetection(JNIEnv* env, jobject context) {
    ResetThroneHuntEvidence();
    if (GetAndroidApiLevel() < 31) {
        SetThroneHuntUnsupported("api", "requires Android 12 or newer");
        return;
    }
    if (env == nullptr || context == nullptr) {
        MarkThroneHuntUnavailable("payload", 0, "JNI environment or Context is null");
        return;
    }
    jclass managerClass = env->FindClass("com/lingqing/trustattestor/ThroneHuntCarrierManager");
    if (managerClass == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        MarkThroneHuntUnavailable("payload", 0, "ThroneHuntCarrierManager is unavailable");
        return;
    }
    jmethodID method = env->GetStaticMethodID(
            managerClass, "runRound", "(Landroid/content/Context;)Ljava/lang/String;");
    if (method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(managerClass);
        MarkThroneHuntUnavailable("payload", 0, "runRound(Context) is unavailable");
        return;
    }
    auto payload = static_cast<jstring>(env->CallStaticObjectMethod(managerClass, method, context));
    env->DeleteLocalRef(managerClass);
    if (env->ExceptionCheck() || payload == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        MarkThroneHuntUnavailable("payload", 0, "runRound(Context) failed or returned null");
        return;
    }
    const char* chars = env->GetStringUTFChars(payload, nullptr);
    if (chars == nullptr) {
        env->DeleteLocalRef(payload);
        MarkThroneHuntUnavailable("payload", 0, "round payload could not be decoded");
        return;
    }
    ApplyRoundPayload(chars);
    env->ReleaseStringUTFChars(payload, chars);
    env->DeleteLocalRef(payload);
}

