#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <iterator>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "checker_internal.h"
#include "jni_helper.h"
#include "logging.h"

namespace {

constexpr int kTargetCount = 4;
// Start with a short screen and pay for the six-round confirmation only when a
// target is elevated, noisy, or incomplete. Ratios are dimensionless, so the
// confirmation rounds may use a larger transaction batch without biasing the
// final median.
constexpr int kInitialSampleRounds = 3;
constexpr int kMaximumSampleRounds = 6;
constexpr int kWarmupIterations = 2;
constexpr int kScreenIterationsPerRound = 8;
constexpr int kConfirmIterationsPerRound = 20;
constexpr int kMinimumInitialValidRounds = 3;
constexpr int kMinimumConfirmedValidRounds = 4;
constexpr double kConfirmationRatio = 1.15;
constexpr double kMaximumScreenRelativeMad = 0.35;
constexpr double kMaximumRelativeMad = 0.35;
constexpr double kMinimumLowerQuartileFactor = 0.85;

constexpr int kLspTransaction = ('_' << 24) | ('L' << 16) | ('S' << 8) | 'P';
constexpr int kSuiTransaction = ('_' << 24) | ('S' << 16) | ('U' << 8) | 'I';
constexpr int kSrTransaction = ('_' << 24) | ('_' << 16) | ('S' << 8) | 'R';
constexpr int kLspPumpkinTransaction = 1857388951;

constexpr std::array<int, kTargetCount> kTransactions{
        kLspTransaction,
        kSuiTransaction,
        kSrTransaction,
        kLspPumpkinTransaction,
};

constexpr std::array<const char*, kTargetCount> kTokens{
        "LSPosed",
        "Default",
        "Default",
        "LSBridge",
};

// Several unknown codes avoid depending on one potentially special Binder path.
constexpr std::array<int, 3> kControlTransactions{
        -1,
        0x5a17c001,
        0x5a17c002,
};

std::array<std::array<double, kMaximumSampleRounds>, kTargetCount> sRoundRatios{};
std::array<double, kTargetCount> sLowerQuartiles{};
uint8_t sReliableTargets = 0;

#if defined(__clang__)
#define TIMING_NOINLINE __attribute__((noinline, used))
#else
#define TIMING_NOINLINE
#endif

uint64_t MonotonicNanos() {
    struct timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

void DeleteLocalRef(JNIEnv* env, jobject ref) {
    if (ref != nullptr) env->DeleteLocalRef(ref);
}

TIMING_NOINLINE double MeasureTransaction(
        JNIEnv* env,
        jobject binder,
        int transaction,
        const char* token,
        int iterations) {
    if (binder == nullptr || iterations <= 0) return 0.0;

    jobject send = env->CallStaticObjectMethod(cl_parcel, mid_obtain);
    jobject reply = env->CallStaticObjectMethod(cl_parcel, mid_obtain);
    if (send == nullptr || reply == nullptr || env->ExceptionCheck()) {
        DeleteLocalRef(env, send);
        DeleteLocalRef(env, reply);
        return 0.0;
    }

    jstring tokenString = env->NewStringUTF(token == nullptr ? "Default" : token);
    jstring payloadString = env->NewStringUTF("hello world");
    if (tokenString == nullptr || payloadString == nullptr || env->ExceptionCheck()) {
        DeleteLocalRef(env, tokenString);
        DeleteLocalRef(env, payloadString);
        DeleteLocalRef(env, send);
        DeleteLocalRef(env, reply);
        return 0.0;
    }

    env->CallVoidMethod(send, mid_write_interface_token, tokenString);
    env->CallVoidMethod(send, mid_write_int, 2);
    env->CallVoidMethod(send, mid_write_string, payloadString);
    env->CallVoidMethod(send, mid_write_strong_binder, binder);
    if (env->ExceptionCheck()) {
        DeleteLocalRef(env, tokenString);
        DeleteLocalRef(env, payloadString);
        DeleteLocalRef(env, send);
        DeleteLocalRef(env, reply);
        return 0.0;
    }

    const uint64_t startedAt = MonotonicNanos();
    for (int i = 0; i < iterations; ++i) {
        env->CallBooleanMethod(binder, mid_transact, transaction, send, reply, 0);
    }
    const uint64_t finishedAt = MonotonicNanos();
    const bool failed = env->ExceptionCheck();

    if (!failed) {
        env->CallVoidMethod(send, mid_recycle);
        env->CallVoidMethod(reply, mid_recycle);
    }
    DeleteLocalRef(env, tokenString);
    DeleteLocalRef(env, payloadString);
    DeleteLocalRef(env, send);
    DeleteLocalRef(env, reply);

    if (failed || startedAt == 0 || finishedAt <= startedAt) return 0.0;
    return static_cast<double>(finishedAt - startedAt) / 1'000'000'000.0;
}

double Median(std::vector<double> values) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const size_t middle = values.size() / 2;
    if ((values.size() & 1U) != 0) return values[middle];
    return (values[middle - 1] + values[middle]) / 2.0;
}

double LowerQuartile(std::vector<double> values) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    return values[(values.size() - 1) / 4];
}

double MedianAbsoluteDeviation(const std::vector<double>& values, double median) {
    std::vector<double> deviations;
    deviations.reserve(values.size());
    for (double value : values) deviations.push_back(std::abs(value - median));
    return Median(std::move(deviations));
}

bool IsValidDuration(double value) {
    return value > 0.0 && std::isfinite(value);
}

TIMING_NOINLINE double ForkAndDetectProcAccess(int processCount, bool trigger) {
    constexpr int64_t kNanosPerSecond = 1'000'000'000LL;
    std::vector<pid_t> pids;
    pids.reserve(processCount);

    for (int i = 0; i < processCount; ++i) {
        const pid_t pid = fork();
        if (pid < 0) {
            MarkProbeUnavailable(0, "device.timing.transaction_fork");
            for (pid_t existingPid : pids) KillAndReap(existingPid);
            return -1.0;
        }
        if (pid == 0) {
            prctl(PR_SET_DUMPABLE, 1);
            pause();
            _exit(0);
        }
        pids.push_back(pid);
    }

    bool triggerReady = true;
    if (trigger) {
        const int fd = open("/system/bin/app_process", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            triggerReady = false;
        } else {
            char byte = 0;
            triggerReady = read(fd, &byte, sizeof(byte)) == sizeof(byte);
            close(fd);
        }
    }

    msleep(25);
    struct timespec current{};
    const bool clockReady = clock_gettime(CLOCK_REALTIME, &current) == 0;
    msleep(5);

    int checked = 0;
    int abnormal = 0;
    if (triggerReady && clockReady) {
        for (pid_t pid : pids) {
            char path[32]{};
            std::snprintf(path, sizeof(path), "/proc/%d", pid);
            struct stat st{};
            if (stat(path, &st) != 0) continue;
            const int64_t delta =
                    static_cast<int64_t>(st.st_atim.tv_sec - current.tv_sec) *
                            kNanosPerSecond +
                    static_cast<int64_t>(st.st_atim.tv_nsec - current.tv_nsec);
            ++checked;
            if (delta < 0) ++abnormal;
        }
    }

    for (pid_t pid : pids) {
        if (!KillAndReap(pid)) MarkProbeUnavailable(0, "device.process_access.reap");
    }
    if (!triggerReady || !clockReady || checked == 0) return -1.0;
    return static_cast<double>(abnormal) / checked;
}

}  // namespace

void InitTransactions(JNIEnv* env) {
    static bool calibrated = false;
    if (calibrated && IsValidDuration(sTransactionRate[0])) {
        LOGD("transaction timing calibration reused from process cache");
        return;
    }
    std::fill(std::begin(sTransactionRate), std::end(sTransactionRate), 0.0);
    sRoundRatios = {};
    sLowerQuartiles = {};
    sReliableTargets = 0;

    jstring serviceName = env->NewStringUTF("activity");
    if (serviceName == nullptr) return;
    jobject binder = env->CallStaticObjectMethod(cl_service_manager, mid_get_service, serviceName);
    env->DeleteLocalRef(serviceName);
    if (binder == nullptr || env->ExceptionCheck()) return;

    for (int control : kControlTransactions) {
        MeasureTransaction(env, binder, control, "Default", kWarmupIterations);
        if (env->ExceptionCheck()) break;
    }
    for (int target = 0; target < kTargetCount && !env->ExceptionCheck(); ++target) {
        MeasureTransaction(
                env,
                binder,
                kTransactions[target],
                kTokens[target],
                kWarmupIterations);
    }

    std::vector<double> baselineSamples;
    baselineSamples.reserve(kMaximumSampleRounds * kTargetCount * 2);

    auto sampleRound = [&](int round, int iterations) {
        // Rotate target order so thermal and scheduler drift do not always favor one probe.
        for (int slot = 0; slot < kTargetCount && !env->ExceptionCheck(); ++slot) {
            const int target = (round + slot) % kTargetCount;
            const int control = kControlTransactions[(round + slot) % kControlTransactions.size()];

            const double before = MeasureTransaction(
                    env, binder, control, "Default", iterations);
            const double measured = MeasureTransaction(
                    env,
                    binder,
                    kTransactions[target],
                    kTokens[target],
                    iterations);
            const double after = MeasureTransaction(
                    env, binder, control, "Default", iterations);

            if (!IsValidDuration(before) || !IsValidDuration(measured) ||
                !IsValidDuration(after)) {
                continue;
            }

            const double baseline = (before + after) / 2.0;
            if (!IsValidDuration(baseline)) continue;
            baselineSamples.push_back(before);
            baselineSamples.push_back(after);
            sRoundRatios[target][round] = measured / baseline;
        }
    };

    for (int round = 0;
         round < kInitialSampleRounds && !env->ExceptionCheck();
         ++round) {
        sampleRound(round, kScreenIterationsPerRound);
    }

    bool needsConfirmation = false;
    for (int target = 0; target < kTargetCount; ++target) {
        std::vector<double> ratios;
        ratios.reserve(kInitialSampleRounds);
        for (int round = 0; round < kInitialSampleRounds; ++round) {
            const double ratio = sRoundRatios[target][round];
            if (IsValidDuration(ratio)) ratios.push_back(ratio);
        }
        if (ratios.size() < kMinimumInitialValidRounds) {
            needsConfirmation = true;
            break;
        }
        const double median = Median(ratios);
        const double mad = MedianAbsoluteDeviation(ratios, median);
        const double relativeMad = median > 0.0 ? mad / median : 1.0;
        if (median >= kConfirmationRatio ||
            !std::isfinite(relativeMad) ||
            relativeMad > kMaximumScreenRelativeMad) {
            needsConfirmation = true;
            break;
        }
    }
    const int sampledRounds = needsConfirmation
            ? kMaximumSampleRounds
            : kInitialSampleRounds;
    if (needsConfirmation) {
        for (int round = kInitialSampleRounds;
             round < kMaximumSampleRounds && !env->ExceptionCheck();
             ++round) {
            sampleRound(round, kConfirmIterationsPerRound);
        }
    }

    env->DeleteLocalRef(binder);
    sTransactionRate[0] = Median(std::move(baselineSamples));
    calibrated = !env->ExceptionCheck() && IsValidDuration(sTransactionRate[0]);

    for (int target = 0; target < kTargetCount; ++target) {
        std::vector<double> validRatios;
        validRatios.reserve(sampledRounds);
        for (int round = 0; round < sampledRounds; ++round) {
            const double ratio = sRoundRatios[target][round];
            if (IsValidDuration(ratio)) validRatios.push_back(ratio);
        }
        const int minimumValidRounds = needsConfirmation
                ? kMinimumConfirmedValidRounds
                : kMinimumInitialValidRounds;
        if (validRatios.size() < static_cast<size_t>(minimumValidRounds)) {
            LOGD("transaction timing target {} inconclusive: samples={}",
                 target, validRatios.size());
            continue;
        }

        const double median = Median(validRatios);
        const double mad = MedianAbsoluteDeviation(validRatios, median);
        const double relativeMad = median > 0.0 ? mad / median : 1.0;
        if (!std::isfinite(relativeMad) || relativeMad > kMaximumRelativeMad) {
            LOGD("transaction timing target {} inconclusive: median={} relative_mad={}",
                 target, median, relativeMad);
            continue;
        }

        sTransactionRate[target + 1] = median;
        sLowerQuartiles[target] = LowerQuartile(std::move(validRatios));
        sReliableTargets |= static_cast<uint8_t>(1U << target);
        LOGD("transaction timing target {}: median={} p25={} relative_mad={}",
             target, median, sLowerQuartiles[target], relativeMad);
    }
    LOGD("transaction timing sampling path: {} rounds={}",
         needsConfirmation ? "confirmed" : "fast", sampledRounds);
}

void FindTransactions() {
    constexpr double kBridgeRate = 1.4;
    constexpr double kSuiRate = 1.7;

    if (!IsValidDuration(sTransactionRate[0])) {
        LOGD("binder transaction timing unavailable");
        return;
    }

    auto isHighConfidence = [](int target, double threshold) {
        const uint8_t bit = static_cast<uint8_t>(1U << target);
        return (sReliableTargets & bit) != 0 &&
               sTransactionRate[target + 1] > threshold &&
               sLowerQuartiles[target] > threshold * kMinimumLowerQuartileFactor;
    };

    const bool lsp = isHighConfidence(0, kBridgeRate);
    const bool sui = isHighConfidence(1, kSuiRate);
    const bool sr = isHighConfidence(2, kBridgeRate);
    const bool pumpkin = isHighConfidence(3, kBridgeRate);

    LOGD("transaction timing result: lsp={} sui={} sr={} pumpkin={} reliable=0x{:02x}",
         lsp, sui, sr, pumpkin, sReliableTargets);
    if (lsp || pumpkin) MarkEvilBridge(2);
    if (sui) MarkEvilBridge(4);
    if (sr) MarkEvilBridge(8);
}

void FindSulist() {
    constexpr int kInitialRounds = 3;
    constexpr int kMaximumRounds = 6;
    constexpr int kInitialProcessesPerSample = 2;
    constexpr int kConfirmProcessesPerSample = 4;
    constexpr int kMinimumInitialValidRounds = 3;
    constexpr int kMinimumConfirmedValidRounds = 4;
    constexpr double kConfirmationDifference = 0.2;
    constexpr double kDetectionDifference = 0.4;
    constexpr double kMaximumMad = 0.25;

    std::vector<double> pairedDifferences;
    pairedDifferences.reserve(kMaximumRounds);
    auto sampleRound = [&](int round, int processCount) {
        double triggered;
        double control;
        if ((round & 1) == 0) {
            triggered = ForkAndDetectProcAccess(processCount, true);
            control = ForkAndDetectProcAccess(processCount, false);
        } else {
            control = ForkAndDetectProcAccess(processCount, false);
            triggered = ForkAndDetectProcAccess(processCount, true);
        }
        if (triggered < 0.0 || control < 0.0) return;
        pairedDifferences.push_back(triggered - control);
    };

    for (int round = 0; round < kInitialRounds; ++round) {
        sampleRound(round, kInitialProcessesPerSample);
    }

    bool needsConfirmation = pairedDifferences.size() < kMinimumInitialValidRounds;
    if (!needsConfirmation) {
        const double initialMedian = Median(pairedDifferences);
        const double initialMad = MedianAbsoluteDeviation(pairedDifferences, initialMedian);
        const bool hasElevatedSample = std::any_of(
                pairedDifferences.begin(),
                pairedDifferences.end(),
                [](double value) { return value >= 0.5; });
        needsConfirmation = initialMedian >= kConfirmationDifference ||
                            initialMad > kMaximumMad ||
                            hasElevatedSample;
    }

    if (needsConfirmation) {
        for (int round = kInitialRounds; round < kMaximumRounds; ++round) {
            sampleRound(round, kConfirmProcessesPerSample);
        }
    }

    const int minimumValidRounds = needsConfirmation
            ? kMinimumConfirmedValidRounds
            : kMinimumInitialValidRounds;
    if (pairedDifferences.size() < static_cast<size_t>(minimumValidRounds)) {
        LOGD("proc access timing inconclusive: samples={}", pairedDifferences.size());
        return;
    }

    const double median = Median(pairedDifferences);
    const double mad = MedianAbsoluteDeviation(pairedDifferences, median);
    LOGD("proc access timing result: median={} mad={} samples={} path={}",
         median, mad, pairedDifferences.size(),
         needsConfirmation ? "confirmed" : "fast");
    if (mad <= kMaximumMad && median >= kDetectionDifference) {
        MarkFutileHide(1u << 6);
    }
}
