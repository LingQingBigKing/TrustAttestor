#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "checker.h"
#include "checker_internal.h"
#include "jni_helper.h"
#include "logging.h"

jobject sDexClassLoader = nullptr;
static void ResetUiScanState(JNIEnv* env) {
    sFoundPermissionLoophole = false;
    sAbnormalEnvironment = false;
    sSurroundingSuspicious = false;
    sInconsistentMount = false;
    sPropertyAreaModified = 0;
    sPropertyItemModified = 0;
    ppid = getppid();
    sFoundInjection = 0;
    sEvilBridge = 0;
    sFutileHide = 0;
    sConventionalTests = 0;
    sDirtySepolicy = 0;
    sKernelSuProbe = 0;
    sKernelSuVersion = 0;
    sKernelSuFlags = 0;
    sKernelSuUapiVersion = 0;
    sKernelSuMagicErrno = 0;
    ResetThroneHuntEvidence();
    sTeeSimulator = 0;
    sReadProc = 0;
    runtime_probe::Reset();
    sAbnormalKey = 0;
    sKeyAttestationFlags = 0;
    mnt_check_appzygote = APP_ZYGOTE_RESULT_UNAVAILABLE;
    sUnavailableProbes.clear();
    sUnavailableProbeSet.clear();
    sAbnormalCount = 0;
    sAbnormalAppliedMask = 0;
    memset(mnt_strings, 0, sizeof(mnt_strings));
}

static uint64_t CollectRiskFingerprint() {
    uint64_t fp = 0;
    fp ^= (uint64_t) sFoundPermissionLoophole << 0;
    fp ^= (uint64_t) sAbnormalEnvironment << 1;
    fp ^= (uint64_t) sSurroundingSuspicious << 2;
    fp ^= (uint64_t) sInconsistentMount << 3;
    fp ^= (uint64_t) sPropertyAreaModified << 4;
    fp ^= (uint64_t) sPropertyItemModified << 8;
    fp ^= (uint64_t) sFoundInjection << 16;
    fp ^= (uint64_t) sEvilBridge << 24;
    fp ^= (uint64_t) (sFutileHide & 0xffffffffu);
    fp ^= (uint64_t) (sConventionalTests & 0xffffffffu) * 0x9E3779B185EBCA87ULL;
    fp ^= (uint64_t) sDirtySepolicy * 0xD6E8FEB86659FD93ULL;
    fp ^= (uint64_t) (sKernelSuProbe & kernelsu_probe::kDetectedMask) *
            0xF1357AEA2E62A9C5ULL;
    fp ^= (uint64_t) sThroneHuntDetected * 0x8CB92BA72F3D8DD7ULL;
    fp ^= (uint64_t) sTeeSimulator * 0xA24BAED4963EE407ULL;
    fp ^= (uint64_t) (sReadProc & kReadProcFindingMask) * 0xC2B2AE3D27D4EB4FULL;
    fp ^= (uint64_t) sAbnormalKey << 48;
    fp ^= sKeyAttestationFlags * 0x94D049BB133111EBULL;
    fp ^= (uint64_t) sUnavailableProbes.size() << 56;
    return fp;
}

static bool EnsureUiScanInitialized(JNIEnv* env, jobject context, std::string &error) {
    if (!VerifyInstalledApkIdentity(env, context, error)) {
        LOGE("APK integrity verification failed: {}", error);
        Crash();
    }

    if (sDexClassLoader == nullptr) {
        auto local_class_loader = LoadDex(env, DEX, DEX_SIZE);
        if (local_class_loader != nullptr) {
            sDexClassLoader = env->NewGlobalRef(local_class_loader);
            env->DeleteLocalRef(local_class_loader);
        }
    }
    if (sDexClassLoader == nullptr) {
        error = "DexClassLoader 初始化失败";
        return false;
    }

    if (!VerifyApkSignatureStructure(env, error)) {
        LOGE("APK signature structure verification failed: {}", error);
        Crash();
    }

    runtime_probe::Run();
    const uint32_t fatal_runtime_integrity =
            sRuntimeIntegrity & runtime_probe::kFatalMask;
    if (fatal_runtime_integrity != 0) {
        LOGE("Runtime integrity gate failed: {:#x}", fatal_runtime_integrity);
        Crash();
    }
    return true;
}

static const char* FindingStatusName(FindingStatus status) {
    switch (status) {
        case FindingStatus::Clean: return "CLEAN";
        case FindingStatus::Detected: return "DETECTED";
        case FindingStatus::Warning: return "WARNING";
        case FindingStatus::Unavailable: return "UNAVAILABLE";
    }
}

static const char* FindingSeverityName(FindingSeverity severity) {
    switch (severity) {
        case FindingSeverity::Info: return "INFO";
        case FindingSeverity::Low: return "LOW";
        case FindingSeverity::Medium: return "MEDIUM";
        case FindingSeverity::High: return "HIGH";
        case FindingSeverity::Critical: return "CRITICAL";
    }
}

static int FindingSeverityValue(FindingSeverity severity) {
    return static_cast<int>(severity);
}

static std::string JsonEscape(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 16);
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (ch < 0x20) escaped += fmt::format("\\u{:04x}", ch);
                else escaped.push_back(static_cast<char>(ch));
        }
    }
    return escaped;
}

static std::string SerializeFinding(const NativeFinding& finding) {
    return fmt::format(
            "{{\"schema\":\"trustattestor.finding/v2\",\"probeId\":\"{}\","
            "\"layer\":{},\"status\":\"{}\",\"severity\":\"{}\","
            "\"data\":{}}}",
            JsonEscape(finding.probeId), finding.layer, FindingStatusName(finding.status),
            FindingSeverityName(finding.severity), finding.dataJson);
}

static int ComputeVisibleIssueCount() {
    const auto findings = BuildAllVisibleFindings();
    return static_cast<int>(std::count_if(findings.begin(), findings.end(), [](const auto& finding) {
        return finding.status == FindingStatus::Detected;
    }));
}

void checker_run(
        JNIEnv *env,
        jobject context,
        jobject callback) {

    if (env == nullptr || context == nullptr || callback == nullptr) {
        return;
    }

    jclass callbackClass = env->GetObjectClass(callback);
    if (callbackClass == nullptr) {
        return;
    }

    jmethodID onNativeEvent = env->GetMethodID(
            callbackClass,
            "onNativeEvent",
            "(IIILjava/lang/String;)V"
    );

    if (onNativeEvent == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        env->DeleteLocalRef(callbackClass);
        return;
    }

    enum NativeEventType {
        STEP_STARTED = 1,
        STEP_FINISHED = 2,
        PROGRESS = 3,
        FINISHED = 4,
        FAILED = 5,
        FINDING = 6,
    };

    auto postEvent = [&](NativeEventType type, int step, int value, const std::string &text) -> bool {
        jstring jtext = env->NewStringUTF(text.c_str());
        if (jtext == nullptr) return false;
        env->CallVoidMethod(callback, onNativeEvent, type, step, value, jtext);
        env->DeleteLocalRef(jtext);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            return false;
        }
        return true;
    };

    auto postProgress = [&](int step, int permille, const std::string &text) -> bool {
        return postEvent(PROGRESS, step, std::clamp(permille, 0, 1000), text);
    };

    auto postStepStarted = [&](int index, const char *title) -> bool {
        return postEvent(STEP_STARTED, index, 0, title);
    };

    auto postStepFinished = [&](int index, bool ok, const std::string &detail) -> bool {
        return postEvent(STEP_FINISHED, index, ok ? 1 : 0, detail);
    };

    auto postFindings = [&](const std::vector<NativeFinding>& findings) -> bool {
        for (const auto& finding : findings) {
            if (!postEvent(FINDING, finding.layer, FindingSeverityValue(finding.severity),
                           SerializeFinding(finding))) return false;
        }
        return true;
    };

    auto failAndReturn = [&](const std::string &msg) {
        postEvent(FAILED, -1, 0, msg);
    };

    auto hasNewRisk = [&](uint64_t before, uint64_t after) -> bool {
        return before != after;
    };

    FindModification();

    SetWo();
    InitProperties();

    InitJNIHelper(env);

    ResetUiScanState(env);

    std::string error;

    struct StepDef {
        const char *title;
        bool keyAttestation;
        void (*run)(JNIEnv *, jobject);
    };

    const StepDef steps[] = {
            {"step.init", false, nullptr},
            {"step.device", false, nullptr},
            {"step.system", false, +[](JNIEnv *e, jobject context) {
                const uint64_t symbolStartedAt = MonotonicMillis();
                InitSymbolList();
                LOGI("symbol initialization completed in {} ms",
                     MonotonicMillis() - symbolStartedAt);
                const uint64_t transactionStartedAt = MonotonicMillis();
                InitTransactions(e);
                LOGI("binder benchmark completed in {} ms",
                     MonotonicMillis() - transactionStartedAt);
                if (e->ExceptionCheck()) return;
                FindReadProcDetection(e, context);
                FindAppZygoteDetection(e, context);
                FindUnload();
                FindPermissionLoophole(e);
                FindNativeBridge();
                FindMemory();
                FindSystemServer(e);
                FindTransactions();
                FindInconsistentMount();
                FindResetProp();
                FindMountInfoLoophole();
            }},
            {"step.hardware", true, nullptr},
    };

    if (!postStepStarted(0, steps[0].title)) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    const uint64_t initializationStartedAt = MonotonicMillis();
    if (!postProgress(0, 80, "progress.init.prepare")) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    if (!postProgress(0, 300, "progress.init.services")) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    if (!postProgress(0, 650, "progress.init.components")) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    const uint64_t dexStartedAt = MonotonicMillis();
    if (!EnsureUiScanInitialized(env, context, error)) {
        failAndReturn("error.init.native");
        env->DeleteLocalRef(callbackClass);
        return;
    }
    LOGI("dex load and APK verification completed in {} ms", MonotonicMillis() - dexStartedAt);

    if (!postProgress(0, 1000, "progress.init.ready")) {
        env->DeleteLocalRef(callbackClass);
        return;
    }
    LOGI("UI scan initialization completed in {} ms", MonotonicMillis() - initializationStartedAt);

    if (!postStepFinished(0, true, "")) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    // Run local checks in their visible order. Device and system probes warm
    // the runtime/Binder pools before the latency-sensitive KeyMint probe.
    // Kotlin schedules L3 cloud only after all three local steps finish.
    for (int i = 1; i <= 2; ++i) {
        auto beforeSnapshot = CaptureRiskSnapshot();
        uint64_t before = CollectRiskFingerprint();

        if (!postStepStarted(i, steps[i].title)) {
            env->DeleteLocalRef(callbackClass);
            return;
        }

        if (i == 1) {
            auto runDeviceProbe = [&](int permille, const char* progress, const char* logName, auto&& probe) -> bool {
                if (!postProgress(i, permille, progress)) return false;
                const uint64_t startedAt = MonotonicMillis();
                probe();
                LOGI("device probe {} completed in {} ms", logName, MonotonicMillis() - startedAt);
                return true;
            };
            if (!runDeviceProbe(100, "progress.device.mount_namespace", "mount namespace", [&] { FindFutileHide(); }) ||
                !runDeviceProbe(300, "progress.device.process_access", "process access", [&] { FindSulist(); }) ||
                !runDeviceProbe(480, "progress.device.kernel_patch", "kernel patch", [&] { FindAPatch(); }) ||
                !runDeviceProbe(650, "progress.device.kernelsu", "KernelSU UAPI", [&] { FindKernelSuProbe(); }) ||
                !runDeviceProbe(760, "progress.device.kernelsu.throne_hunt", "KernelSU throne hunt", [&] { FindThroneHuntDetection(env, context); }) ||
                !runDeviceProbe(850, "progress.device.environment", "environment", [&] { ConventionalTests(env); }) ||
                !postProgress(i, 1000, "progress.device.complete")) {
                env->DeleteLocalRef(callbackClass);
                return;
            }
        } else if (steps[i].run != nullptr) {
            if (!postProgress(i, 120, "progress.system.zygote")) {
                env->DeleteLocalRef(callbackClass);
                return;
            }
            steps[i].run(env, context);
            if (!postProgress(i, 720, "progress.system.collect")) {
                env->DeleteLocalRef(callbackClass);
                return;
            }
            if (!postProgress(i, 860, "progress.system.teesim")) {
                env->DeleteLocalRef(callbackClass);
                return;
            }
            FindTeeSimulator(env, context);
            if (!postProgress(i, 1000, "progress.system.complete")) {
                env->DeleteLocalRef(callbackClass);
                return;
            }
        }

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            failAndReturn("error.step.execution");
            env->DeleteLocalRef(callbackClass);
            return;
        }

        uint64_t after = CollectRiskFingerprint();
        bool ok = !hasNewRisk(before, after);

        const auto afterSnapshot = CaptureRiskSnapshot();
        const auto findings = BuildStepFindings(i, beforeSnapshot, afterSnapshot);
        if (!postFindings(findings)) {
            env->DeleteLocalRef(callbackClass);
            return;
        }

        if (!postStepFinished(i, ok, {})) {
            env->DeleteLocalRef(callbackClass);
            return;
        }

    }

    auto runHardwareStep = [&]() -> bool {
        if (!postStepStarted(3, steps[3].title)) return false;

        const auto hardwareBeforeSnapshot = CaptureRiskSnapshot();
        const uint64_t hardwareBefore = CollectRiskFingerprint();

        if (!postProgress(3, 20, "progress.hardware.connect_keystore")) return false;

        auto keyAttestationClass = FindClassFromLoader(
                env, sDexClassLoader, "com/lingqing/trustattestor/KeyAttestation");
        bool keyReady = false;
        if (keyAttestationClass != nullptr) {
            auto keyAttestationMethod = env->GetStaticMethodID(
                    keyAttestationClass,
                    "run",
                    "(Landroid/content/Context;Ljava/lang/Object;)I");
            if (keyAttestationMethod != nullptr) {
                PrepareKeystoreTimingClock(env);
                const jint check = env->CallStaticIntMethod(
                        keyAttestationClass, keyAttestationMethod, context, callback);
                if (!env->ExceptionCheck()) {
                    LOGD("KeyAttestation {}", check);
                    keyReady = ApplyKeyAttestationResult(check);
                    auto flagsMethod = env->GetStaticMethodID(
                            keyAttestationClass,
                            "getLastProbeFlags",
                            "()J");
                    if (flagsMethod != nullptr && !env->ExceptionCheck()) {
                        const auto flags = static_cast<uint64_t>(
                                env->CallStaticLongMethod(keyAttestationClass, flagsMethod));
                        if (!env->ExceptionCheck()) {
                            LOGD("KeyAttestation probe flags={:#x}", flags);
                            MarkKeyAttestationFlags(flags);
                        }
                    }
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    CollectKeystoreProbeStatus(env, keyAttestationClass);
                }
            }
            env->DeleteLocalRef(keyAttestationClass);
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            failAndReturn("error.hardware.execution");
            return false;
        }

        if (!keyReady) {
            const std::vector<NativeFinding> unavailable = {{
                    "hardware.attestation.unavailable", 2, FindingStatus::Unavailable,
                    FindingSeverity::High, "{}",
            }};
            if (!postFindings(unavailable) ||
                !postStepFinished(3, false, {})) {
                return false;
            }
            failAndReturn("error.hardware.unavailable");
            return false;
        }

        const uint64_t hardwareAfter = CollectRiskFingerprint();
        const bool hardwareOk = !hasNewRisk(hardwareBefore, hardwareAfter);
        const auto hardwareFindings = BuildStepFindings(
                3, hardwareBeforeSnapshot, CaptureRiskSnapshot());

        return postFindings(hardwareFindings) &&
               postStepFinished(3, hardwareOk, {});
    };

    if (!runHardwareStep()) {
        env->DeleteLocalRef(callbackClass);
        return;
    }

    bool finalSuccess =
            sUnavailableProbes.empty() &&
            !sFoundPermissionLoophole &&
            !sSurroundingSuspicious &&
            !sFoundInjection &&
            !sAbnormalEnvironment &&
            !sInconsistentMount &&
            !((sPropertyAreaModified << 4) | sPropertyItemModified) &&
            !sEvilBridge &&
            !sFutileHide &&
            !sConventionalTests &&
            !sDirtySepolicy &&
            !(sKernelSuProbe & kernelsu_probe::kDetectedMask) &&
            !sThroneHuntDetected &&
            !sTeeSimulator &&
            !(sReadProc & kReadProcFindingMask) &&
            !sAbnormalKey;

    int visibleIssueCount = ComputeVisibleIssueCount();
    if (!postEvent(FINISHED, visibleIssueCount, finalSuccess ? 1 : 0, "scan.finished")) {
        failAndReturn("error.result.finalize");
        env->DeleteLocalRef(callbackClass);
        return;
    }

    env->DeleteLocalRef(callbackClass);
}

JNIEXPORT jint JNICALL TrustAttestorReadProcProbe_check(JNIEnv*, jobject) {
    return static_cast<jint>(ReadProcProbeCheck());
}

JNIEXPORT jint JNICALL TrustAttestorZygotePreload_check(JNIEnv* env, jobject) {
    return static_cast<jint>(RunZygotePreloadProbe(env));
}

jstring checker_collect_cloud_device_evidence(JNIEnv* env) {
    const auto json = CollectCloudDeviceEvidenceJson();
    return env->NewStringUTF(json.c_str());
}

jstring checker_create_cloud_attestation(
        JNIEnv* env,
        jobject context,
        jbyteArray challenge,
        jbyteArray payload_digest) {
    const auto json = CreateCloudAttestationJson(
            env, context, challenge, payload_digest);
    return env->NewStringUTF(json.c_str());
}

jbyteArray checker_cloud_sha256(JNIEnv* env, jbyteArray payload) {
    return ComputeCloudSha256(env, payload);
}

jboolean checker_verify_cloud_verdict(
        JNIEnv* env,
        jbyteArray payload,
        jbyteArray signature,
        jbyteArray public_key) {
    return VerifyCloudVerdictSignature(env, payload, signature, public_key)
            ? JNI_TRUE : JNI_FALSE;
}
