#pragma once

#include <array>
#include <cstdint>
#include <initializer_list>
#include <jni.h>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern uint32_t sReadProc;
extern uint8_t sTeeSimulator;
extern bool sFoundPermissionLoophole;
extern bool sAbnormalEnvironment;
extern bool sSurroundingSuspicious;
extern bool sInconsistentMount;
extern uint8_t sPropertyAreaModified;
extern uint8_t sPropertyItemModified;
extern double sTransactionRate[5];
extern uint8_t sFoundInjection;
extern uint8_t sEvilBridge;
extern uint32_t sFutileHide;
extern uint32_t sConventionalTests;
extern uint32_t sDirtySepolicy;
extern uint32_t sRuntimeIntegrity;
extern uint32_t sKernelSuProbe;
extern uint32_t sKernelSuVersion;
extern uint32_t sKernelSuFlags;
extern uint32_t sKernelSuUapiVersion;
extern int32_t sKernelSuMagicErrno;
extern bool sThroneHuntAvailable;
extern bool sThroneHuntDetected;
extern uint32_t sThroneHuntBaselineOpen;
extern uint32_t sThroneHuntBaselineAccess;
extern uint32_t sThroneHuntFinalOpen;
extern uint32_t sThroneHuntFinalAccess;
extern uint32_t sThroneHuntFinalRaw;
extern uint32_t sThroneHuntFinalInvalid;
extern std::string sThroneHuntDetail;
extern uint8_t sAbnormalKey;
extern uint64_t sKeyAttestationFlags;
struct ProbeMetric {
    std::string name;
    uint64_t value;
};

struct UnavailableProbe {
    std::string probeId;
    int layer;
    std::string stage;
    int errorNumber = 0;
    std::string detail;
    std::vector<ProbeMetric> metrics;
};

extern std::vector<UnavailableProbe> sUnavailableProbes;
extern std::unordered_set<std::string> sUnavailableProbeSet;
extern std::unordered_map<std::string, void*> sSymbolList;
extern uintptr_t gStackStart;
extern uintptr_t gStackEnd;
extern char mnt_strings[1024];
extern jobject sDexClassLoader;
extern int mnt_check_appzygote;
extern pid_t ppid;
extern int sAbnormalCount;
extern uint64_t sAbnormalAppliedMask;
extern std::string app_apk_path;

namespace kernelsu_probe {

// These bits describe observations made from an untrusted app process.  The
// fd name is a kernel-created anon-inode name; GET_INFO is the authoritative
// confirmation when seccomp/SELinux permits the ioctl.
constexpr uint32_t FD_PRESENT = 1u << 0;
constexpr uint32_t FD_INFO_VALID = 1u << 1;
constexpr uint32_t MAGIC_FD_PRESENT = 1u << 2;
constexpr uint32_t MAGIC_INFO_VALID = 1u << 3;
constexpr uint32_t FD_SCAN_UNAVAILABLE = 1u << 4;
constexpr uint32_t MAGIC_PROBE_UNAVAILABLE = 1u << 5;

constexpr uint32_t kDetectedMask =
        FD_PRESENT | FD_INFO_VALID | MAGIC_FD_PRESENT | MAGIC_INFO_VALID;

}  // namespace kernelsu_probe

enum AppZygoteCheckFlag : uint32_t {
    APP_ZYGOTE_ATTR_TIME_ANOMALY = 1u << 0,
    APP_ZYGOTE_TMPFS_PERMISSION = 1u << 1,
    APP_ZYGOTE_MOUNT_ART_GAP = 1u << 2,
    APP_ZYGOTE_MOUNT_BOOT_GAP = 1u << 3,
    APP_ZYGOTE_MOUNT_DATA_GAP = 1u << 4,
    APP_ZYGOTE_RESULT_UNAVAILABLE = 1u << 5,

    APP_ZYGOTE_SEPOLICY_PROBE_ERROR = 1u << 6,
    APP_ZYGOTE_SELINUX_PERMISSIVE = 1u << 7,
    APP_ZYGOTE_SYSTEM_SERVER_EXECMEM = 1u << 8,
    APP_ZYGOTE_AOSP_SU = 1u << 9,
    APP_ZYGOTE_ADB_ROOT = 1u << 10,
    APP_ZYGOTE_MAGISK_POLICY = 1u << 11,
    APP_ZYGOTE_KERNEL_SU_POLICY = 1u << 12,
    APP_ZYGOTE_LSPOSED_POLICY = 1u << 13,
    APP_ZYGOTE_XPOSED_POLICY = 1u << 14,
    APP_ZYGOTE_ZYGISK_NEXT_POLICY = 1u << 15,
    APP_ZYGOTE_STATUS_NOT_ENFORCING = 1u << 16,
    APP_ZYGOTE_DENY_UNKNOWN_DISABLED = 1u << 17,
    APP_ZYGOTE_POLICYLOAD_ANOMALY = 1u << 18,
    APP_ZYGOTE_AVD_SEQUENCE_ANOMALY = 1u << 19,
    APP_ZYGOTE_APATCH_POLICY = 1u << 20,
    APP_ZYGOTE_USERSPACE_QUERY_TAMPERED = 1u << 21,
    APP_ZYGOTE_ACCESS_ORACLE_TAMPERED = 1u << 22,
    APP_ZYGOTE_STATUS_CHANNEL_TAMPERED = 1u << 23,
    APP_ZYGOTE_POLICY_VIEW_TAMPERED = 1u << 24,
    APP_ZYGOTE_TEESIM_KEYSTORE_POLICY = 1u << 25,
    APP_ZYGOTE_CHECK_COMPLETED = 1u << 30,
};

constexpr uint32_t kDirtySepolicyFindingMask =
        APP_ZYGOTE_SELINUX_PERMISSIVE |
        APP_ZYGOTE_SYSTEM_SERVER_EXECMEM |
        APP_ZYGOTE_AOSP_SU |
        APP_ZYGOTE_ADB_ROOT |
        APP_ZYGOTE_MAGISK_POLICY |
        APP_ZYGOTE_KERNEL_SU_POLICY |
        APP_ZYGOTE_LSPOSED_POLICY |
        APP_ZYGOTE_XPOSED_POLICY |
        APP_ZYGOTE_ZYGISK_NEXT_POLICY |
        APP_ZYGOTE_STATUS_NOT_ENFORCING |
        APP_ZYGOTE_DENY_UNKNOWN_DISABLED |
        APP_ZYGOTE_POLICYLOAD_ANOMALY |
        APP_ZYGOTE_AVD_SEQUENCE_ANOMALY |
        APP_ZYGOTE_APATCH_POLICY |
        APP_ZYGOTE_USERSPACE_QUERY_TAMPERED |
        APP_ZYGOTE_ACCESS_ORACLE_TAMPERED |
        APP_ZYGOTE_STATUS_CHANNEL_TAMPERED |
        APP_ZYGOTE_POLICY_VIEW_TAMPERED |
        APP_ZYGOTE_TEESIM_KEYSTORE_POLICY;

namespace teesim_probe {
constexpr uint8_t ADMIN_PROTOCOL = 1u << 0;
constexpr uint8_t CONTROL_SOCKET = 1u << 1;
constexpr uint8_t RS_SOTER_PROTOCOL = 1u << 2;
}

namespace runtime_probe {

enum Flag : uint32_t {
    FRIDA_PROTOCOL = 1u << 0,
    FRIDA_RUNTIME_MARKER = 1u << 1,
    NATIVE_API_OWNER_MISMATCH = 1u << 2,

    FRIDA_PORT_OPEN = 1u << 16,
    NATIVE_API_OWNER_INCOMPLETE = 1u << 17,
    CHECK_COMPLETED = 1u << 30,
};

constexpr uint32_t kFatalMask =
        FRIDA_PROTOCOL |
        FRIDA_RUNTIME_MARKER |
        NATIVE_API_OWNER_MISMATCH;

struct Evidence {
    std::string fridaProtocol;
    std::vector<std::string> fridaRuntime;
    std::vector<std::string> apiOwnerMismatches;
    std::vector<std::string> apiOwnerVerified;
    std::vector<std::string> apiOwnerUnavailable;
};

extern Evidence evidence;

void Reset();
void Run();

}  // namespace runtime_probe

enum class FindingStatus { Clean, Detected, Warning, Unavailable };
enum class FindingSeverity { Info, Low, Medium, High, Critical };

struct NativeFinding {
    std::string probeId;
    int layer;
    FindingStatus status;
    FindingSeverity severity;
    std::string dataJson;
};

struct RiskSnapshot {
    bool foundPermissionLoophole;
    bool abnormalEnvironment;
    bool surroundingSuspicious;
    bool inconsistentMount;
    uint8_t propertyAreaModified;
    uint8_t propertyItemModified;
    uint8_t foundInjection;
    uint8_t evilBridge;
    uint32_t futileHide;
    uint32_t conventionalTests;
    uint32_t dirtySepolicy;
    uint32_t kernelSuProbe;
    uint32_t kernelSuVersion;
    uint32_t kernelSuFlags;
    uint32_t kernelSuUapiVersion;
    bool throneHuntAvailable;
    bool throneHuntDetected;
    uint32_t throneHuntBaselineOpen;
    uint32_t throneHuntBaselineAccess;
    uint32_t throneHuntFinalOpen;
    uint32_t throneHuntFinalAccess;
    uint32_t throneHuntFinalRaw;
    uint32_t throneHuntFinalInvalid;
    uint8_t teeSimulator;
    uint32_t readProc;
    uint8_t abnormalKey;
    uint64_t keyAttestationFlags;
    size_t unavailableCount;
};

RiskSnapshot CaptureRiskSnapshot();
std::vector<NativeFinding> BuildStepFindings(
        int nativeStep,
        const RiskSnapshot& before,
        const RiskSnapshot& after);
std::vector<NativeFinding> BuildAllVisibleFindings();

void MarkProbeUnavailable(int layer, std::string_view probe_id);
void MarkProbeUnavailable(
        int layer,
        std::string_view probe_id,
        std::string_view stage,
        int error_number,
        std::string_view detail,
        std::initializer_list<ProbeMetric> metrics = {});
void MarkPermissionLoophole();
void MarkAbnormalEnvironment();
void MarkSurroundingSuspicious();
void MarkInconsistentMount();
void AddPropertyAreaModified();
void AddPropertyItemModified();
void MarkInjection(uint8_t mask);
void MarkEvilBridge(uint8_t mask);
void MarkFutileHide(uint32_t mask);
void MarkConventional(uint32_t mask);
void MarkDirtySepolicy(uint32_t mask);
void MarkKernelSuProbe(uint32_t mask);
void MarkAbnormalKey(uint8_t mask);
void MarkKeyAttestationFlags(uint64_t flags);
void PrepareKeystoreTimingClock(JNIEnv* env);
void CollectKeystoreProbeStatus(JNIEnv* env, jclass key_attestation_class);
void MarkTeeSimulator(uint8_t finding);
void MarkRuntimeIntegrity(uint32_t finding);

void msleep(int milliseconds);
uint64_t MonotonicMillis();
bool WaitPidWithTimeout(pid_t pid, int* status, int timeout_ms);
bool KillAndReap(pid_t pid, int timeout_ms = 500);
void InitProperties();
void InitSymbolList();
void FindUnload();
void InitTransactions(JNIEnv* env);
int GetAndroidApiLevel();
void FindAppZygoteDetection(JNIEnv* env, jobject context);
uint32_t CheckDirtySepolicy(JNIEnv* env);
void FindPermissionLoophole(JNIEnv* env);
void FindNativeBridge();
void FindInconsistentMount();
void FindMemory();
int GetFileCon(const char* path, std::string& ctx);
void FindResetProp();
void FindSystemServer(JNIEnv* env);
void FindTransactions();
void FindModification();
void FindMntStrings();
void FindFutileHide();
void ConventionalTests(JNIEnv* env);
void FindAPatch();
void FindMountInfoLoophole();
void FindKernelSuProbe();
void FindThroneHuntDetection(JNIEnv* env, jobject context);
void ResetThroneHuntEvidence();
void FindSulist();
bool ApplyKeyAttestationResult(jint check);
bool VerifyInstalledApkIdentity(JNIEnv* env, jobject context, std::string& error);
bool VerifyApkSignatureStructure(JNIEnv* env, std::string& error);
uint32_t RunZygotePreloadProbe(JNIEnv* env);

enum ReadProcCheckFlag : uint32_t {
    READPROC_RESULT_UNAVAILABLE = 1u << 0,
    READPROC_GID_3009 = 1u << 1,
    READPROC_MOUNTINFO_READABLE = 1u << 2,
    READPROC_CMDLINE_READABLE = 1u << 3,
    READPROC_STATUS_READABLE = 1u << 4,
    READPROC_MAPS_READABLE = 1u << 5,

    READPROC_MOUNT_TRACE = 1u << 8,
    READPROC_NAMESPACE_VIEW_MISMATCH = 1u << 9,
    READPROC_ZN_DAEMON = 1u << 10,
    READPROC_LSPD = 1u << 11,
    READPROC_TRICKY_STORE = 1u << 12,
    READPROC_TEESIM_RS_DAEMON = 1u << 13,
    READPROC_TEESIM_RS_HOOK = 1u << 14,
    READPROC_CHECK_COMPLETED = 1u << 30,
};

constexpr uint32_t kReadProcFindingMask =
        READPROC_MOUNT_TRACE |
        READPROC_NAMESPACE_VIEW_MISMATCH |
        READPROC_ZN_DAEMON |
        READPROC_LSPD |
        READPROC_TRICKY_STORE |
        READPROC_TEESIM_RS_DAEMON |
        READPROC_TEESIM_RS_HOOK;

void MarkReadProc(uint32_t finding);
void FindReadProcDetection(JNIEnv* env, jobject context);
uint32_t ReadProcProbeCheck();
void FindTeeSimulator(JNIEnv* env, jobject context);

std::array<uint8_t, 32> ComputeSha256(std::string_view data);

struct KernelIdentity {
    std::string release;
    std::string buildVersion;
    std::string machine;
    bool available = false;
};

KernelIdentity CollectKernelIdentity();
std::string CollectCloudDeviceEvidenceJson();
std::string CreateCloudAttestationJson(
        JNIEnv* env,
        jobject context,
        jbyteArray challenge,
        jbyteArray payload_digest);
jbyteArray ComputeCloudSha256(JNIEnv* env, jbyteArray payload);
bool VerifyCloudVerdictSignature(
        JNIEnv* env,
        jbyteArray payload,
        jbyteArray signature,
        jbyteArray public_key);

enum KeyAttestationProbeFlag : uint64_t {
    KEY_ATTEST_VERIFIED_BOOT_STATE = 1ULL << 8,
    KEY_ATTEST_ATTEST_KEY_DESCRIPTOR_DELEGATION = 1ULL << 13,
    KEY_ATTEST_TRUST_VALIDATION = 1ULL << 14,
    KEY_ATTEST_SECURITY_LEVEL = 1ULL << 15,
    KEY_ATTEST_USER_AUTH_METADATA = 1ULL << 35,
    KEY_ATTEST_SIGNING_LINEAGE = 1ULL << 36,
    KEY_ATTEST_OPERATION_SEMANTICS = 1ULL << 37,
    KEY_ATTEST_DEVICE_PROPERTIES = 1ULL << 38,
    KEY_ATTEST_ALGORITHM_DIFFERENTIAL = 1ULL << 39,
    KEY_ATTEST_STRONGBOX_DIFFERENTIAL = 1ULL << 40,
    KEY_ATTEST_KEYMINT_BOUNDARY = 1ULL << 41,
    KEY_ATTEST_CERT_VALIDITY = 1ULL << 42,
    KEY_ATTEST_BUILD_FINGERPRINT = 1ULL << 43,
    KEY_ATTEST_RSA_CONFORMANCE = 1ULL << 44,
    KEY_ATTEST_HMAC_CONFORMANCE = 1ULL << 45,
    KEY_ATTEST_ECDH_CONFORMANCE = 1ULL << 46,
    KEY_ATTEST_AES_CONFORMANCE = 1ULL << 47,
    KEY_ATTEST_ENTRY_SEMANTICS = 1ULL << 48,
    KEY_ATTEST_MAIN_BINDING = 1ULL << 49,
    KEY_ATTEST_OPERATION_ISOLATION = 1ULL << 50,
    KEY_ATTEST_ISOLATED_CHAIN = 1ULL << 51,
    KEY_ATTEST_CHAIN_READ_STABILITY = 1ULL << 52,
    KEY_ATTEST_CERTIFICATE_ROUND_TRIP = 1ULL << 53,
    KEY_ATTEST_BINDER_LOCALITY = 1ULL << 54,
    KEY_ATTEST_INTERFACE_TOKEN_DISPATCH = 1ULL << 55,
    KEY_ATTEST_PARAMETER_FINGERPRINT = 1ULL << 56,
    KEY_ATTEST_TEESIM_PARAMETER_FINGERPRINT = 1ULL << 57,
    KEY_ATTEST_REPLY_LAG = 1ULL << 58,
    KEY_ATTEST_READ_PATH_TIMING = 1ULL << 59,
    KEY_ATTEST_KEY_ID_CONSISTENCY = 1ULL << 60,
    KEY_ATTEST_KEYSTORE_LEDGER = 1ULL << 61,

};

constexpr uint64_t kDetailedKeyAttestationFindingMask =
        KEY_ATTEST_VERIFIED_BOOT_STATE |
        KEY_ATTEST_ATTEST_KEY_DESCRIPTOR_DELEGATION |
        KEY_ATTEST_TRUST_VALIDATION |
        KEY_ATTEST_SECURITY_LEVEL |
        KEY_ATTEST_USER_AUTH_METADATA |
        KEY_ATTEST_SIGNING_LINEAGE |
        KEY_ATTEST_OPERATION_SEMANTICS |
        KEY_ATTEST_DEVICE_PROPERTIES |
        KEY_ATTEST_ALGORITHM_DIFFERENTIAL |
        KEY_ATTEST_STRONGBOX_DIFFERENTIAL |
        KEY_ATTEST_KEYMINT_BOUNDARY |
        KEY_ATTEST_CERT_VALIDITY |
        KEY_ATTEST_BUILD_FINGERPRINT |
        KEY_ATTEST_RSA_CONFORMANCE |
        KEY_ATTEST_HMAC_CONFORMANCE |
        KEY_ATTEST_ECDH_CONFORMANCE |
        KEY_ATTEST_AES_CONFORMANCE |
        KEY_ATTEST_ENTRY_SEMANTICS |
        KEY_ATTEST_MAIN_BINDING |
        KEY_ATTEST_OPERATION_ISOLATION |
        KEY_ATTEST_ISOLATED_CHAIN |
        KEY_ATTEST_CHAIN_READ_STABILITY |
        KEY_ATTEST_CERTIFICATE_ROUND_TRIP |
        KEY_ATTEST_BINDER_LOCALITY |
        KEY_ATTEST_INTERFACE_TOKEN_DISPATCH |
        KEY_ATTEST_PARAMETER_FINGERPRINT |
        KEY_ATTEST_TEESIM_PARAMETER_FINGERPRINT |
        KEY_ATTEST_REPLY_LAG |
        KEY_ATTEST_READ_PATH_TIMING |
        KEY_ATTEST_KEY_ID_CONSISTENCY |
        KEY_ATTEST_KEYSTORE_LEDGER;
