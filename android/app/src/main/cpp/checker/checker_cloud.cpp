#include <jni.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <sys/syscall.h>
#include <unistd.h>

#include <fmt/format.h>

#include "checker_internal.h"
#include "logging.h"

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include "api/_system_properties.h"

namespace {

constexpr char kLegacyCloudAlias[] = "TrustAttestorCloud";
constexpr char kCloudAliasPrefix[] = "TrustAttestorCloud_";
constexpr char kAttestationOid[] = "1.3.6.1.4.1.11129.2.1.17";
constexpr int kPurposeSign = 4;
constexpr int kPurposeVerify = 8;
constexpr size_t kCloudAliasRandomBytes = 16;
constexpr size_t kMaxKeystoreAliases = 4096;

std::mutex gCloudAttestationMutex;

bool ClearJniException(JNIEnv* env) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}

std::string GenerateCloudAlias() {
    std::array<uint8_t, kCloudAliasRandomBytes> random{};
    size_t offset = 0;
    while (offset < random.size()) {
        const auto count = static_cast<ssize_t>(syscall(
                __NR_getrandom,
                random.data() + offset,
                random.size() - offset,
                0));
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return {};
    }

    constexpr char kHex[] = "0123456789abcdef";
    std::string alias{kCloudAliasPrefix};
    alias.reserve(alias.size() + random.size() * 2);
    for (const uint8_t byte : random) {
        alias.push_back(kHex[byte >> 4]);
        alias.push_back(kHex[byte & 0x0f]);
    }
    return alias;
}

bool DeleteExistingCloudAliases(
        JNIEnv* env,
        jobject key_store,
        jmethodID aliases_method,
        jmethodID contains_alias,
        jmethodID delete_entry) {
    jclass enumeration_class = env->FindClass("java/util/Enumeration");
    if (enumeration_class == nullptr || ClearJniException(env)) return false;
    jmethodID has_more = env->GetMethodID(enumeration_class, "hasMoreElements", "()Z");
    jmethodID next_element = env->GetMethodID(
            enumeration_class,
            "nextElement",
            "()Ljava/lang/Object;");
    if (has_more == nullptr || next_element == nullptr || ClearJniException(env)) return false;

    std::vector<std::string> stale_aliases{kLegacyCloudAlias};
    jobject enumeration = env->CallObjectMethod(key_store, aliases_method);
    if (enumeration == nullptr || ClearJniException(env)) return false;
    size_t inspected = 0;
    while (env->CallBooleanMethod(enumeration, has_more) == JNI_TRUE) {
        if (ClearJniException(env) || ++inspected > kMaxKeystoreAliases) return false;
        auto alias_object = reinterpret_cast<jstring>(
                env->CallObjectMethod(enumeration, next_element));
        if (alias_object == nullptr || ClearJniException(env)) return false;
        const char* chars = env->GetStringUTFChars(alias_object, nullptr);
        if (chars == nullptr || ClearJniException(env)) return false;
        const std::string_view candidate{chars};
        if (candidate.starts_with(kCloudAliasPrefix) &&
            candidate != kLegacyCloudAlias) {
            stale_aliases.emplace_back(candidate);
        }
        env->ReleaseStringUTFChars(alias_object, chars);
        env->DeleteLocalRef(alias_object);
    }
    if (ClearJniException(env)) return false;

    for (const auto& stale_alias : stale_aliases) {
        jstring stale = env->NewStringUTF(stale_alias.c_str());
        if (stale == nullptr || ClearJniException(env)) return false;
        const bool exists = env->CallBooleanMethod(key_store, contains_alias, stale) == JNI_TRUE;
        if (ClearJniException(env)) {
            env->DeleteLocalRef(stale);
            return false;
        }
        if (!exists) {
            env->DeleteLocalRef(stale);
            continue;
        }
        env->CallVoidMethod(key_store, delete_entry, stale);
        if (ClearJniException(env)) {
            env->DeleteLocalRef(stale);
            return false;
        }
        const bool still_exists = env->CallBooleanMethod(key_store, contains_alias, stale) == JNI_TRUE;
        const bool verification_failed = ClearJniException(env);
        env->DeleteLocalRef(stale);
        if (verification_failed || still_exists) return false;
    }
    return true;
}

std::string JsonEscape(std::string_view value) {
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

std::string JsonStringOrNull(std::string_view value) {
    return value.empty() ? "null" : fmt::format("\"{}\"", JsonEscape(value));
}

std::string ReadProperty(const char* key) {
    std::array<char, PROP_VALUE_MAX> value{};
    const int length = __system_property_get(key, value.data());
    if (length <= 0) return {};
    return {value.data(), static_cast<size_t>(length)};
}

std::string FirstProperty(std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        auto value = ReadProperty(key);
        if (!value.empty()) return value;
    }
    return {};
}

std::vector<std::string> PropertyCandidates(std::initializer_list<const char*> keys) {
    std::vector<std::string> values;
    for (const char* key : keys) {
        const auto value = ReadProperty(key);
        if (value.empty() || std::find(values.begin(), values.end(), value) != values.end()) continue;
        values.push_back(value);
    }
    return values;
}

std::vector<std::string> SplitCommaList(std::string_view value) {
    std::vector<std::string> values;
    size_t offset = 0;
    while (offset <= value.size()) {
        const size_t comma = value.find(',', offset);
        const size_t end = comma == std::string_view::npos ? value.size() : comma;
        size_t start = offset;
        while (start < end && value[start] == ' ') ++start;
        size_t trimmed_end = end;
        while (trimmed_end > start && value[trimmed_end - 1] == ' ') --trimmed_end;
        if (trimmed_end > start) values.emplace_back(value.substr(start, trimmed_end - start));
        if (comma == std::string_view::npos) break;
        offset = comma + 1;
    }
    return values;
}

std::string JsonStringArray(const std::vector<std::string>& values) {
    std::string json = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) json += ',';
        json += fmt::format("\"{}\"", JsonEscape(values[i]));
    }
    json += ']';
    return json;
}

std::vector<uint8_t> CopyByteArray(JNIEnv* env, jbyteArray value) {
    if (value == nullptr) return {};
    const jsize size = env->GetArrayLength(value);
    if (size < 0 || ClearJniException(env)) return {};
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (size > 0) {
        env->GetByteArrayRegion(value, 0, size, reinterpret_cast<jbyte*>(bytes.data()));
        if (ClearJniException(env)) return {};
    }
    return bytes;
}

jbyteArray MakeByteArray(JNIEnv* env, const uint8_t* data, size_t size) {
    if (size > static_cast<size_t>(INT32_MAX)) return nullptr;
    jbyteArray result = env->NewByteArray(static_cast<jsize>(size));
    if (result == nullptr || ClearJniException(env)) return nullptr;
    if (size > 0) {
        env->SetByteArrayRegion(
                result,
                0,
                static_cast<jsize>(size),
                reinterpret_cast<const jbyte*>(data));
        if (ClearJniException(env)) return nullptr;
    }
    return result;
}

std::string Base64Encode(const uint8_t* data, size_t size) {
    static constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((size + 2) / 3) * 4);
    for (size_t offset = 0; offset < size; offset += 3) {
        const uint32_t first = data[offset];
        const uint32_t second = offset + 1 < size ? data[offset + 1] : 0;
        const uint32_t third = offset + 2 < size ? data[offset + 2] : 0;
        const uint32_t value = (first << 16u) | (second << 8u) | third;
        output.push_back(alphabet[(value >> 18u) & 0x3fu]);
        output.push_back(alphabet[(value >> 12u) & 0x3fu]);
        output.push_back(offset + 1 < size ? alphabet[(value >> 6u) & 0x3fu] : '=');
        output.push_back(offset + 2 < size ? alphabet[value & 0x3fu] : '=');
    }
    return output;
}

struct DerNode {
    uint8_t tag_class = 0;
    bool constructed = false;
    uint32_t tag_number = 0;
    size_t value_offset = 0;
    size_t value_length = 0;
    size_t next_offset = 0;
};

bool ReadDerNode(const std::vector<uint8_t>& data, size_t offset, size_t end, DerNode& node) {
    if (offset >= end || end > data.size()) return false;
    const uint8_t first = data[offset++];
    node.tag_class = first >> 6u;
    node.constructed = (first & 0x20u) != 0;
    node.tag_number = first & 0x1fu;
    if (node.tag_number == 0x1fu) {
        node.tag_number = 0;
        int count = 0;
        while (offset < end && count++ < 5) {
            const uint8_t part = data[offset++];
            if (node.tag_number > (UINT32_MAX >> 7u)) return false;
            node.tag_number = (node.tag_number << 7u) | (part & 0x7fu);
            if ((part & 0x80u) == 0) break;
        }
        if (count == 0 || (data[offset - 1] & 0x80u) != 0) return false;
    }
    if (offset >= end) return false;
    uint64_t length = data[offset++];
    if ((length & 0x80u) != 0) {
        const size_t length_bytes = static_cast<size_t>(length & 0x7fu);
        if (length_bytes == 0 || length_bytes > 4 || offset + length_bytes > end) return false;
        length = 0;
        for (size_t i = 0; i < length_bytes; ++i) length = (length << 8u) | data[offset++];
    }
    if (length > end - offset) return false;
    node.value_offset = offset;
    node.value_length = static_cast<size_t>(length);
    node.next_offset = offset + node.value_length;
    return true;
}

bool FindInteger(
        const std::vector<uint8_t>& data,
        size_t start,
        size_t end,
        uint64_t& value,
        int depth) {
    if (depth > 12) return false;
    size_t offset = start;
    while (offset < end) {
        DerNode node;
        if (!ReadDerNode(data, offset, end, node)) return false;
        if (node.tag_class == 0 && node.tag_number == 2 && node.value_length > 0 &&
            node.value_length <= sizeof(uint64_t) + 1) {
            size_t integer_offset = node.value_offset;
            size_t integer_length = node.value_length;
            if (integer_length > sizeof(uint64_t) && data[integer_offset] == 0) {
                ++integer_offset;
                --integer_length;
            }
            if (integer_length <= sizeof(uint64_t)) {
                value = 0;
                for (size_t i = 0; i < integer_length; ++i) {
                    value = (value << 8u) | data[integer_offset + i];
                }
                return true;
            }
        }
        if ((node.constructed || (node.tag_class == 0 && node.tag_number == 4)) &&
            FindInteger(data, node.value_offset, node.next_offset, value, depth + 1)) {
            return true;
        }
        offset = node.next_offset;
    }
    return false;
}

struct CertificatePatchLevels {
    uint64_t os_version = 0;
    uint64_t os_patch = 0;
    uint64_t vendor_patch = 0;
    uint64_t boot_patch = 0;
};

void WalkPatchLevels(
        const std::vector<uint8_t>& data,
        size_t start,
        size_t end,
        CertificatePatchLevels& levels,
        int depth) {
    if (depth > 16) return;
    size_t offset = start;
    while (offset < end) {
        DerNode node;
        if (!ReadDerNode(data, offset, end, node)) return;
        if (node.tag_class == 2 &&
            (node.tag_number == 705 || node.tag_number == 706 ||
             node.tag_number == 718 || node.tag_number == 719)) {
            uint64_t value = 0;
            if (FindInteger(data, node.value_offset, node.next_offset, value, depth + 1)) {
                uint64_t* target = nullptr;
                if (node.tag_number == 705) target = &levels.os_version;
                if (node.tag_number == 706) target = &levels.os_patch;
                if (node.tag_number == 718) target = &levels.vendor_patch;
                if (node.tag_number == 719) target = &levels.boot_patch;
                if (target != nullptr) *target = std::max(*target, value);
            }
        }
        if (node.constructed || (node.tag_class == 0 && node.tag_number == 4)) {
            WalkPatchLevels(data, node.value_offset, node.next_offset, levels, depth + 1);
        }
        offset = node.next_offset;
    }
}

std::string FormatOsVersion(uint64_t value) {
    if (value == 0) return {};
    return fmt::format("{}.{}.{}", value / 10000u, (value / 100u) % 100u, value % 100u);
}

std::string FormatPatchLevel(uint64_t value) {
    if (value < 100000u) return {};
    const uint64_t year = value / (value >= 10000000u ? 10000u : 100u);
    const uint64_t month = value >= 10000000u ? (value / 100u) % 100u : value % 100u;
    if (month < 1 || month > 12) return {};
    if (value >= 10000000u) {
        const uint64_t day = value % 100u;
        if (day < 1 || day > 31) return {};
        return fmt::format("{:04}-{:02}-{:02}", year, month, day);
    }
    return fmt::format("{:04}-{:02}", year, month);
}

std::string PatchLevelsJson(const CertificatePatchLevels& levels) {
    auto number_or_null = [](uint64_t value) {
        return value == 0 ? std::string("null") : std::to_string(value);
    };
    return fmt::format(
            "{{\"systemVersion\":{},\"systemVersionRaw\":{},"
            "\"systemPatchLevel\":{},\"systemPatchLevelRaw\":{},"
            "\"vendorPatchLevel\":{},\"vendorPatchLevelRaw\":{},"
            "\"bootPatchLevel\":{},\"bootPatchLevelRaw\":{}}}",
            JsonStringOrNull(FormatOsVersion(levels.os_version)),
            number_or_null(levels.os_version),
            JsonStringOrNull(FormatPatchLevel(levels.os_patch)),
            number_or_null(levels.os_patch),
            JsonStringOrNull(FormatPatchLevel(levels.vendor_patch)),
            number_or_null(levels.vendor_patch),
            JsonStringOrNull(FormatPatchLevel(levels.boot_patch)),
            number_or_null(levels.boot_patch));
}

}  // namespace

std::string CollectCloudDeviceEvidenceJson() {
    const auto kernel = CollectKernelIdentity();
    const auto abi_all = SplitCommaList(ReadProperty("ro.product.cpu.abilist"));
    const auto abi_32 = SplitCommaList(ReadProperty("ro.product.cpu.abilist32"));
    const auto abi_64 = SplitCommaList(ReadProperty("ro.product.cpu.abilist64"));
    const auto incremental_candidates = PropertyCandidates({
            "ro.build.version.incremental",
            "ro.config.lgsi.fp.incremental"});

    return fmt::format(
            "{{\"schema\":\"trustattestor.native-device/v1\","
            "\"device\":{{"
            "\"model\":{},\"product\":{},\"device\":{},\"board\":{},"
            "\"manufacturer\":{},\"brand\":{},\"sku\":{}}},"
            "\"os\":{{"
            "\"release\":{},\"releaseOrCodename\":{},\"sdk\":{},"
            "\"buildId\":{},\"incremental\":{},\"incrementalCandidates\":{},\"securityPatch\":{},"
            "\"vendorSecurityPatch\":{},\"buildTime\":{},\"buildTimeUtc\":{},"
            "\"vendorBuildTimeUtc\":{},\"bootImageBuildTimeUtc\":{},"
            "\"buildType\":{},\"buildTags\":{},\"instructionSet\":{},"
            "\"fingerprint\":{}}},"
            "\"processor\":{{"
            "\"hardware\":{},\"boardPlatform\":{},\"socManufacturer\":{},\"socModel\":{},"
            "\"supportedAbis\":{},\"supportedAbis32\":{},\"supportedAbis64\":{}}},"
            "\"kernel\":{{"
            "\"release\":{},\"buildVersion\":{},\"machine\":{}}},"
            "\"boot\":{{"
            "\"vbmetaDeviceState\":{},\"verifiedBootState\":{},\"flashLocked\":{},"
            "\"verityMode\":{},\"vbmetaDigest\":{}}}}}",
            JsonStringOrNull(ReadProperty("ro.product.model")),
            JsonStringOrNull(FirstProperty({"ro.product.name", "ro.product.system.name"})),
            JsonStringOrNull(ReadProperty("ro.product.device")),
            JsonStringOrNull(ReadProperty("ro.product.board")),
            JsonStringOrNull(ReadProperty("ro.product.manufacturer")),
            JsonStringOrNull(ReadProperty("ro.product.brand")),
            JsonStringOrNull(FirstProperty({"ro.boot.hardware.sku", "ro.product.hardware.sku", "ro.boot.product.hardware.sku"})),
            JsonStringOrNull(ReadProperty("ro.build.version.release")),
            JsonStringOrNull(FirstProperty({"ro.build.version.release_or_codename", "ro.build.version.codename"})),
            JsonStringOrNull(ReadProperty("ro.build.version.sdk")),
            JsonStringOrNull(ReadProperty("ro.build.id")),
            JsonStringOrNull(ReadProperty("ro.build.version.incremental")),
            JsonStringArray(incremental_candidates),
            JsonStringOrNull(ReadProperty("ro.build.version.security_patch")),
            JsonStringOrNull(FirstProperty({"ro.vendor.build.security_patch", "vendor.build.security_patch"})),
            JsonStringOrNull(ReadProperty("ro.build.date")),
            JsonStringOrNull(ReadProperty("ro.build.date.utc")),
            JsonStringOrNull(ReadProperty("ro.vendor.build.date.utc")),
            JsonStringOrNull(ReadProperty("ro.bootimage.build.date.utc")),
            JsonStringOrNull(ReadProperty("ro.build.type")),
            JsonStringOrNull(ReadProperty("ro.build.tags")),
            JsonStringOrNull(ReadProperty("ro.product.cpu.abi")),
            JsonStringOrNull(ReadProperty("ro.build.fingerprint")),
            JsonStringOrNull(ReadProperty("ro.hardware")),
            JsonStringOrNull(ReadProperty("ro.board.platform")),
            JsonStringOrNull(ReadProperty("ro.soc.manufacturer")),
            JsonStringOrNull(ReadProperty("ro.soc.model")),
            JsonStringArray(abi_all),
            JsonStringArray(abi_32),
            JsonStringArray(abi_64),
            JsonStringOrNull(kernel.available ? kernel.release : ""),
            JsonStringOrNull(kernel.available ? kernel.buildVersion : ""),
            JsonStringOrNull(kernel.available ? kernel.machine : ""),
            JsonStringOrNull(FirstProperty({"ro.boot.vbmeta.device_state", "vendor.boot.vbmeta.device_state"})),
            JsonStringOrNull(FirstProperty({"ro.boot.verifiedbootstate", "vendor.boot.verifiedbootstate"})),
            JsonStringOrNull(ReadProperty("ro.boot.flash.locked")),
            JsonStringOrNull(ReadProperty("ro.boot.veritymode")),
            JsonStringOrNull(ReadProperty("ro.boot.vbmeta.digest")));
}

jbyteArray ComputeCloudSha256(JNIEnv* env, jbyteArray payload) {
    const auto bytes = CopyByteArray(env, payload);
    if (payload == nullptr || (bytes.empty() && env->GetArrayLength(payload) != 0)) return nullptr;
    const auto digest = ComputeSha256(std::string_view(
            reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    return MakeByteArray(env, digest.data(), digest.size());
}

bool VerifyCloudVerdictSignature(
        JNIEnv* env,
        jbyteArray payload,
        jbyteArray signature,
        jbyteArray public_key) {
    if (payload == nullptr || signature == nullptr || public_key == nullptr) return false;
    if (env->PushLocalFrame(32) != JNI_OK) return false;
    bool verified = false;
    do {
        jclass key_spec_class = env->FindClass("java/security/spec/X509EncodedKeySpec");
        jclass key_factory_class = env->FindClass("java/security/KeyFactory");
        jclass signature_class = env->FindClass("java/security/Signature");
        if (key_spec_class == nullptr || key_factory_class == nullptr || signature_class == nullptr ||
            ClearJniException(env)) break;

        jmethodID key_spec_ctor = env->GetMethodID(key_spec_class, "<init>", "([B)V");
        jmethodID get_key_factory = env->GetStaticMethodID(
                key_factory_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyFactory;");
        jmethodID generate_public = env->GetMethodID(
                key_factory_class,
                "generatePublic",
                "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;");
        jmethodID get_signature = env->GetStaticMethodID(
                signature_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;");
        jmethodID init_verify = env->GetMethodID(
                signature_class,
                "initVerify",
                "(Ljava/security/PublicKey;)V");
        jmethodID update = env->GetMethodID(signature_class, "update", "([B)V");
        jmethodID verify = env->GetMethodID(signature_class, "verify", "([B)Z");
        if (key_spec_ctor == nullptr || get_key_factory == nullptr || generate_public == nullptr ||
            get_signature == nullptr || init_verify == nullptr || update == nullptr || verify == nullptr ||
            ClearJniException(env)) break;

        jobject key_spec = env->NewObject(key_spec_class, key_spec_ctor, public_key);
        jstring ec = env->NewStringUTF("EC");
        jobject key_factory = env->CallStaticObjectMethod(key_factory_class, get_key_factory, ec);
        jobject public_key_object = key_factory == nullptr
                ? nullptr : env->CallObjectMethod(key_factory, generate_public, key_spec);
        jstring algorithm = env->NewStringUTF("SHA256withECDSA");
        jobject verifier = env->CallStaticObjectMethod(signature_class, get_signature, algorithm);
        if (key_spec == nullptr || key_factory == nullptr || public_key_object == nullptr ||
            verifier == nullptr || ClearJniException(env)) break;

        env->CallVoidMethod(verifier, init_verify, public_key_object);
        env->CallVoidMethod(verifier, update, payload);
        verified = env->CallBooleanMethod(verifier, verify, signature) == JNI_TRUE;
        if (ClearJniException(env)) verified = false;
    } while (false);
    env->PopLocalFrame(nullptr);
    return verified;
}

std::string CreateCloudAttestationJson(
        JNIEnv* env,
        jobject context,
        jbyteArray challenge,
        jbyteArray payload_digest) {
    (void)context;
    if (challenge == nullptr || payload_digest == nullptr ||
        env->GetArrayLength(challenge) <= 0 || env->GetArrayLength(payload_digest) != 32) {
        ClearJniException(env);
        return {};
    }
    std::lock_guard<std::mutex> lock(gCloudAttestationMutex);
    if (env->PushLocalFrame(128) != JNI_OK) return {};

    std::string result;
    jobject key_store = nullptr;
    jstring alias = nullptr;
    jmethodID delete_entry = nullptr;
    jmethodID contains_alias = nullptr;
    do {
        jclass key_store_class = env->FindClass("java/security/KeyStore");
        jclass builder_class = env->FindClass("android/security/keystore/KeyGenParameterSpec$Builder");
        jclass key_pair_generator_class = env->FindClass("java/security/KeyPairGenerator");
        jclass ec_spec_class = env->FindClass("java/security/spec/ECGenParameterSpec");
        jclass signature_class = env->FindClass("java/security/Signature");
        jclass certificate_class = env->FindClass("java/security/cert/Certificate");
        jclass x509_class = env->FindClass("java/security/cert/X509Certificate");
        jclass string_class = env->FindClass("java/lang/String");
        if (key_store_class == nullptr || builder_class == nullptr ||
            key_pair_generator_class == nullptr || ec_spec_class == nullptr ||
            signature_class == nullptr || certificate_class == nullptr ||
            x509_class == nullptr || string_class == nullptr || ClearJniException(env)) break;

        jmethodID get_key_store = env->GetStaticMethodID(
                key_store_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;");
        jmethodID load = env->GetMethodID(
                key_store_class,
                "load",
                "(Ljava/security/KeyStore$LoadStoreParameter;)V");
        delete_entry = env->GetMethodID(key_store_class, "deleteEntry", "(Ljava/lang/String;)V");
        contains_alias = env->GetMethodID(
                key_store_class,
                "containsAlias",
                "(Ljava/lang/String;)Z");
        jmethodID aliases_method = env->GetMethodID(
                key_store_class,
                "aliases",
                "()Ljava/util/Enumeration;");
        jmethodID get_chain = env->GetMethodID(
                key_store_class,
                "getCertificateChain",
                "(Ljava/lang/String;)[Ljava/security/cert/Certificate;");
        jmethodID get_key = env->GetMethodID(
                key_store_class,
                "getKey",
                "(Ljava/lang/String;[C)Ljava/security/Key;");
        if (get_key_store == nullptr || load == nullptr || delete_entry == nullptr ||
            contains_alias == nullptr || aliases_method == nullptr || get_chain == nullptr ||
            get_key == nullptr || ClearJniException(env)) break;

        jstring android_key_store = env->NewStringUTF("AndroidKeyStore");
        key_store = env->CallStaticObjectMethod(key_store_class, get_key_store, android_key_store);
        if (key_store == nullptr || ClearJniException(env)) break;
        env->CallVoidMethod(key_store, load, nullptr);
        if (ClearJniException(env)) break;
        if (!DeleteExistingCloudAliases(
                    env,
                    key_store,
                    aliases_method,
                    contains_alias,
                    delete_entry)) {
            LOGE("Failed to remove existing cloud attestation aliases");
            break;
        }
        const std::string alias_name = GenerateCloudAlias();
        if (alias_name.empty()) {
            LOGE("Failed to generate random cloud attestation alias");
            break;
        }
        alias = env->NewStringUTF(alias_name.c_str());
        if (alias == nullptr || ClearJniException(env)) break;

        jmethodID builder_ctor = env->GetMethodID(builder_class, "<init>", "(Ljava/lang/String;I)V");
        jmethodID set_algorithm = env->GetMethodID(
                builder_class,
                "setAlgorithmParameterSpec",
                "(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
        jmethodID set_digests = env->GetMethodID(
                builder_class,
                "setDigests",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
        jmethodID set_challenge = env->GetMethodID(
                builder_class,
                "setAttestationChallenge",
                "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;");
        jmethodID build = env->GetMethodID(
                builder_class,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;");
        jmethodID ec_spec_ctor = env->GetMethodID(ec_spec_class, "<init>", "(Ljava/lang/String;)V");
        if (builder_ctor == nullptr || set_algorithm == nullptr || set_digests == nullptr ||
            set_challenge == nullptr || build == nullptr || ec_spec_ctor == nullptr ||
            ClearJniException(env)) break;

        jobject builder = env->NewObject(
                builder_class,
                builder_ctor,
                alias,
                kPurposeSign | kPurposeVerify);
        jstring curve_name = env->NewStringUTF("secp256r1");
        jobject curve_spec = env->NewObject(ec_spec_class, ec_spec_ctor, curve_name);
        jobjectArray digests = env->NewObjectArray(1, string_class, nullptr);
        jstring sha256 = env->NewStringUTF("SHA-256");
        env->SetObjectArrayElement(digests, 0, sha256);
        if (builder == nullptr || curve_spec == nullptr || digests == nullptr ||
            ClearJniException(env)) break;
        env->CallObjectMethod(builder, set_algorithm, curve_spec);
        env->CallObjectMethod(builder, set_digests, digests);
        env->CallObjectMethod(builder, set_challenge, challenge);
        jobject key_spec = env->CallObjectMethod(builder, build);
        if (key_spec == nullptr || ClearJniException(env)) break;

        jmethodID get_generator = env->GetStaticMethodID(
                key_pair_generator_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;");
        jmethodID initialize = env->GetMethodID(
                key_pair_generator_class,
                "initialize",
                "(Ljava/security/spec/AlgorithmParameterSpec;)V");
        jmethodID generate = env->GetMethodID(
                key_pair_generator_class,
                "generateKeyPair",
                "()Ljava/security/KeyPair;");
        if (get_generator == nullptr || initialize == nullptr || generate == nullptr ||
            ClearJniException(env)) break;
        jstring ec_name = env->NewStringUTF("EC");
        jobject generator = env->CallStaticObjectMethod(
                key_pair_generator_class,
                get_generator,
                ec_name,
                android_key_store);
        if (generator == nullptr || ClearJniException(env)) break;
        env->CallVoidMethod(generator, initialize, key_spec);
        jobject key_pair = env->CallObjectMethod(generator, generate);
        if (key_pair == nullptr || ClearJniException(env)) break;

        jobjectArray chain = reinterpret_cast<jobjectArray>(
                env->CallObjectMethod(key_store, get_chain, alias));
        jobject private_key = env->CallObjectMethod(key_store, get_key, alias, nullptr);
        if (chain == nullptr || private_key == nullptr || ClearJniException(env)) break;
        const jsize chain_length = env->GetArrayLength(chain);
        if (chain_length <= 0 || ClearJniException(env)) break;

        jmethodID get_signature = env->GetStaticMethodID(
                signature_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;");
        jmethodID init_sign = env->GetMethodID(
                signature_class,
                "initSign",
                "(Ljava/security/PrivateKey;)V");
        jmethodID update = env->GetMethodID(signature_class, "update", "([B)V");
        jmethodID sign = env->GetMethodID(signature_class, "sign", "()[B");
        jmethodID get_encoded = env->GetMethodID(certificate_class, "getEncoded", "()[B");
        jmethodID get_extension = env->GetMethodID(
                x509_class,
                "getExtensionValue",
                "(Ljava/lang/String;)[B");
        if (get_signature == nullptr || init_sign == nullptr || update == nullptr ||
            sign == nullptr || get_encoded == nullptr || get_extension == nullptr ||
            ClearJniException(env)) break;

        jstring signature_name = env->NewStringUTF("SHA256withECDSA");
        jobject signer = env->CallStaticObjectMethod(signature_class, get_signature, signature_name);
        if (signer == nullptr || ClearJniException(env)) break;
        env->CallVoidMethod(signer, init_sign, private_key);
        env->CallVoidMethod(signer, update, payload_digest);
        auto signature_bytes = reinterpret_cast<jbyteArray>(env->CallObjectMethod(signer, sign));
        if (signature_bytes == nullptr || ClearJniException(env)) break;
        const auto signature_vector = CopyByteArray(env, signature_bytes);
        if (signature_vector.empty()) break;

        std::vector<std::string> encoded_chain;
        encoded_chain.reserve(static_cast<size_t>(chain_length));
        CertificatePatchLevels patch_levels;
        for (jsize i = 0; i < chain_length; ++i) {
            jobject certificate = env->GetObjectArrayElement(chain, i);
            auto encoded = certificate == nullptr ? nullptr : reinterpret_cast<jbyteArray>(
                    env->CallObjectMethod(certificate, get_encoded));
            if (encoded == nullptr || ClearJniException(env)) {
                encoded_chain.clear();
                break;
            }
            const auto encoded_vector = CopyByteArray(env, encoded);
            if (encoded_vector.empty()) {
                encoded_chain.clear();
                break;
            }
            encoded_chain.push_back(Base64Encode(encoded_vector.data(), encoded_vector.size()));
            if (i == 0) {
                jstring oid = env->NewStringUTF(kAttestationOid);
                auto extension = reinterpret_cast<jbyteArray>(
                        env->CallObjectMethod(certificate, get_extension, oid));
                if (!ClearJniException(env) && extension != nullptr) {
                    const auto extension_vector = CopyByteArray(env, extension);
                    if (!extension_vector.empty()) {
                        WalkPatchLevels(
                                extension_vector,
                                0,
                                extension_vector.size(),
                                patch_levels,
                                0);
                    }
                }
            }
        }
        if (encoded_chain.size() != static_cast<size_t>(chain_length)) break;

        result = fmt::format(
                "{{\"schema\":\"trustattestor.native-cloud-proof/v1\","
                "\"signatureAlgorithm\":\"SHA256withECDSA\","
                "\"signedPayload\":\"SHA256(canonical-core)\","
                "\"signature\":\"{}\",\"certificateChain\":{},"
                "\"certificatePatchLevels\":{}}}",
                Base64Encode(signature_vector.data(), signature_vector.size()),
                JsonStringArray(encoded_chain),
                PatchLevelsJson(patch_levels));
    } while (false);

    // Cleanup must remain callable even when key generation or certificate
    // retrieval left a pending Java exception on the JNI environment.
    ClearJniException(env);
    if (key_store != nullptr && alias != nullptr && delete_entry != nullptr) {
        env->CallVoidMethod(key_store, delete_entry, alias);
        bool cleanup_failed = ClearJniException(env);
        if (!cleanup_failed && contains_alias != nullptr) {
            cleanup_failed = env->CallBooleanMethod(key_store, contains_alias, alias) == JNI_TRUE;
            cleanup_failed = ClearJniException(env) || cleanup_failed;
        }
        if (cleanup_failed) {
            LOGE("Failed to remove one-time cloud attestation alias");
            result.clear();
        }
    }
    env->PopLocalFrame(nullptr);
    return result;
}
