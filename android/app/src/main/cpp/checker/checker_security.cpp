#include <android/native_activity.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <ranges>
#include <limits>
#include <string>
#include <string_view>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <sys/utsname.h>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>

#include "android_runtime.hpp"
#include "checker.h"
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
#include <mntent.h>


using namespace std::string_literals;
using namespace std::string_view_literals;

namespace {

constexpr char kExpectedPackageName[] = "com.lingqing.trustattestor";
constexpr uint32_t kZipEocdSignature = 0x06054b50;
constexpr uint32_t kApkSignatureSchemeV2Id = 0x7109871a;
constexpr size_t kZipEocdSize = 22;
constexpr size_t kMaxZipCommentSize = 0xffff;
constexpr uint64_t kMaxSigningBlockSize = 32u * 1024u * 1024u;
constexpr char kApkSigningBlockMagic[] = "APK Sig Block 42";

struct AndroidAppPaths {
    std::string package_name;
    std::string code_path;
    std::string resource_path;
    std::string context_source_path;
    std::string context_public_source_path;
    std::string package_manager_source_path;
    std::string package_manager_public_source_path;
    std::string data_path;
    std::string package_manager_data_path;
    std::string files_path;
};

struct Sha256Context {
    std::array<uint32_t, 8> state{
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::array<uint8_t, 64> block{};
    size_t block_size = 0;
    uint64_t transformed_bits = 0;
};

constexpr std::array<uint32_t, 64> kSha256RoundConstants{
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr uint32_t RotateRight(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32u - bits));
}

void Sha256Transform(Sha256Context& context) {
    std::array<uint32_t, 64> words{};
    for (size_t i = 0; i < 16; ++i) {
        const size_t offset = i * 4;
        words[i] = (static_cast<uint32_t>(context.block[offset]) << 24u) |
                   (static_cast<uint32_t>(context.block[offset + 1]) << 16u) |
                   (static_cast<uint32_t>(context.block[offset + 2]) << 8u) |
                   static_cast<uint32_t>(context.block[offset + 3]);
    }
    for (size_t i = 16; i < words.size(); ++i) {
        const uint32_t s0 = RotateRight(words[i - 15], 7) ^
                            RotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3u);
        const uint32_t s1 = RotateRight(words[i - 2], 17) ^
                            RotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10u);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    uint32_t a = context.state[0];
    uint32_t b = context.state[1];
    uint32_t c = context.state[2];
    uint32_t d = context.state[3];
    uint32_t e = context.state[4];
    uint32_t f = context.state[5];
    uint32_t g = context.state[6];
    uint32_t h = context.state[7];
    for (size_t i = 0; i < words.size(); ++i) {
        const uint32_t upper1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
        const uint32_t choose = (e & f) ^ (~e & g);
        const uint32_t temp1 = h + upper1 + choose + kSha256RoundConstants[i] + words[i];
        const uint32_t upper0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = upper0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    context.state[0] += a;
    context.state[1] += b;
    context.state[2] += c;
    context.state[3] += d;
    context.state[4] += e;
    context.state[5] += f;
    context.state[6] += g;
    context.state[7] += h;
    context.transformed_bits += 512;
}

std::array<uint8_t, 32> Sha256(const uint8_t* data, size_t size) {
    Sha256Context context;
    for (size_t i = 0; i < size; ++i) {
        context.block[context.block_size++] = data[i];
        if (context.block_size == context.block.size()) {
            Sha256Transform(context);
            context.block_size = 0;
        }
    }

    const uint64_t total_bits = context.transformed_bits + context.block_size * 8u;
    context.block[context.block_size++] = 0x80;
    if (context.block_size > 56) {
        std::fill(context.block.begin() + static_cast<ptrdiff_t>(context.block_size),
                  context.block.end(), 0);
        Sha256Transform(context);
        context.block_size = 0;
    }
    std::fill(context.block.begin() + static_cast<ptrdiff_t>(context.block_size),
              context.block.begin() + 56, 0);
    for (size_t i = 0; i < 8; ++i) {
        context.block[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8u));
    }
    Sha256Transform(context);

    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < context.state.size(); ++i) {
        digest[i * 4] = static_cast<uint8_t>(context.state[i] >> 24u);
        digest[i * 4 + 1] = static_cast<uint8_t>(context.state[i] >> 16u);
        digest[i * 4 + 2] = static_cast<uint8_t>(context.state[i] >> 8u);
        digest[i * 4 + 3] = static_cast<uint8_t>(context.state[i]);
    }
    return digest;
}

bool DecodeHexDigest(std::string_view hex, std::array<uint8_t, 32>& digest) {
    if (hex.size() != digest.size() * 2) return false;
    auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < digest.size(); ++i) {
        const int high = nibble(hex[i * 2]);
        const int low = nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        digest[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool ConstantTimeEqual(const std::array<uint8_t, 32>& left,
                       const std::array<uint8_t, 32>& right) {
    uint8_t difference = 0;
    for (size_t i = 0; i < left.size(); ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

bool ConsumeJniException(JNIEnv* env, std::string& error, std::string_view message) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    error.assign(message);
    return true;
}

bool CopyJavaString(JNIEnv* env, jstring value, std::string& output,
                    std::string& error, std::string_view label) {
    if (value == nullptr) {
        error = std::string(label) + "为空";
        return false;
    }
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) {
        ConsumeJniException(env, error, std::string(label) + "读取失败");
        if (error.empty()) error = std::string(label) + "读取失败";
        return false;
    }
    output.assign(chars);
    env->ReleaseStringUTFChars(value, chars);
    return true;
}

bool CallStringMethod(JNIEnv* env, jobject object, jclass object_class,
                      const char* method_name, std::string& output,
                      std::string& error, std::string_view label) {
    jmethodID method = env->GetMethodID(object_class, method_name, "()Ljava/lang/String;");
    if (method == nullptr || ConsumeJniException(env, error, std::string(label) + "方法不可用")) {
        if (error.empty()) error = std::string(label) + "方法不可用";
        return false;
    }
    auto value = static_cast<jstring>(env->CallObjectMethod(object, method));
    if (ConsumeJniException(env, error, std::string(label) + "读取异常")) return false;
    const bool success = CopyJavaString(env, value, output, error, label);
    if (value != nullptr) env->DeleteLocalRef(value);
    return success;
}

bool CopyStringField(JNIEnv* env, jobject object, const char* field_name,
                     std::string& output, std::string& error,
                     std::string_view label) {
    jclass object_class = env->GetObjectClass(object);
    if (object_class == nullptr || ConsumeJniException(env, error, std::string(label) + "类型不可用")) {
        if (error.empty()) error = std::string(label) + "类型不可用";
        return false;
    }
    jfieldID field = env->GetFieldID(object_class, field_name, "Ljava/lang/String;");
    if (field == nullptr || ConsumeJniException(env, error, std::string(label) + "字段不可用")) {
        env->DeleteLocalRef(object_class);
        if (error.empty()) error = std::string(label) + "字段不可用";
        return false;
    }
    auto value = static_cast<jstring>(env->GetObjectField(object, field));
    if (ConsumeJniException(env, error, std::string(label) + "读取异常")) {
        env->DeleteLocalRef(object_class);
        return false;
    }
    const bool success = CopyJavaString(env, value, output, error, label);
    if (value != nullptr) env->DeleteLocalRef(value);
    env->DeleteLocalRef(object_class);
    return success;
}

bool CopyFilePath(JNIEnv* env, jobject file, std::string& output,
                  std::string& error, std::string_view label) {
    if (file == nullptr) {
        error = std::string(label) + "为空";
        return false;
    }
    jclass file_class = env->GetObjectClass(file);
    if (file_class == nullptr || ConsumeJniException(env, error, std::string(label) + "类型不可用")) {
        if (error.empty()) error = std::string(label) + "类型不可用";
        return false;
    }
    const bool success = CallStringMethod(
            env, file, file_class, "getCanonicalPath", output, error, label);
    env->DeleteLocalRef(file_class);
    return success;
}

bool CollectAndroidAppPaths(JNIEnv* env, jobject context, AndroidAppPaths& paths,
                            std::string& error) {
    jclass context_class = env->GetObjectClass(context);
    if (context_class == nullptr || ConsumeJniException(env, error, "Context 类型不可用")) {
        if (error.empty()) error = "Context 类型不可用";
        return false;
    }

    bool success = CallStringMethod(env, context, context_class, "getPackageName",
                                    paths.package_name, error, "包名") &&
                   CallStringMethod(env, context, context_class, "getPackageCodePath",
                                    paths.code_path, error, "APK code path") &&
                   CallStringMethod(env, context, context_class, "getPackageResourcePath",
                                    paths.resource_path, error, "APK resource path");
    if (!success) {
        env->DeleteLocalRef(context_class);
        return false;
    }

    jmethodID get_application_info = env->GetMethodID(
            context_class, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jmethodID get_package_manager = env->GetMethodID(
            context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID get_data_dir = env->GetMethodID(
            context_class, "getDataDir", "()Ljava/io/File;");
    jmethodID get_files_dir = env->GetMethodID(
            context_class, "getFilesDir", "()Ljava/io/File;");
    if (get_application_info == nullptr || get_package_manager == nullptr ||
        get_data_dir == nullptr || get_files_dir == nullptr ||
        ConsumeJniException(env, error, "Context 路径接口不可用")) {
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "Context 路径接口不可用";
        return false;
    }

    jobject context_app_info = env->CallObjectMethod(context, get_application_info);
    jobject package_manager = env->CallObjectMethod(context, get_package_manager);
    jobject data_dir = env->CallObjectMethod(context, get_data_dir);
    jobject files_dir = env->CallObjectMethod(context, get_files_dir);
    if (ConsumeJniException(env, error, "应用路径读取异常") ||
        context_app_info == nullptr || package_manager == nullptr ||
        data_dir == nullptr || files_dir == nullptr) {
        if (context_app_info != nullptr) env->DeleteLocalRef(context_app_info);
        if (package_manager != nullptr) env->DeleteLocalRef(package_manager);
        if (data_dir != nullptr) env->DeleteLocalRef(data_dir);
        if (files_dir != nullptr) env->DeleteLocalRef(files_dir);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "应用路径读取失败";
        return false;
    }

    success = CopyStringField(env, context_app_info, "sourceDir",
                              paths.context_source_path, error, "ApplicationInfo.sourceDir") &&
              CopyStringField(env, context_app_info, "publicSourceDir",
                              paths.context_public_source_path, error,
                              "ApplicationInfo.publicSourceDir") &&
              CopyFilePath(env, data_dir, paths.data_path, error, "应用数据目录") &&
              CopyFilePath(env, files_dir, paths.files_path, error, "应用 files 目录");
    if (!success) {
        env->DeleteLocalRef(context_app_info);
        env->DeleteLocalRef(package_manager);
        env->DeleteLocalRef(data_dir);
        env->DeleteLocalRef(files_dir);
        env->DeleteLocalRef(context_class);
        return false;
    }

    jclass package_manager_class = env->GetObjectClass(package_manager);
    jmethodID get_pm_application_info = package_manager_class == nullptr ? nullptr : env->GetMethodID(
            package_manager_class, "getApplicationInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
    jstring package_name = env->NewStringUTF(paths.package_name.c_str());
    if (package_manager_class == nullptr || get_pm_application_info == nullptr ||
        package_name == nullptr || ConsumeJniException(env, error, "PackageManager 路径接口不可用")) {
        if (package_name != nullptr) env->DeleteLocalRef(package_name);
        if (package_manager_class != nullptr) env->DeleteLocalRef(package_manager_class);
        env->DeleteLocalRef(context_app_info);
        env->DeleteLocalRef(package_manager);
        env->DeleteLocalRef(data_dir);
        env->DeleteLocalRef(files_dir);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageManager 路径接口不可用";
        return false;
    }
    jobject pm_app_info = env->CallObjectMethod(package_manager, get_pm_application_info,
                                                 package_name, 0);
    if (ConsumeJniException(env, error, "PackageManager 路径读取异常") || pm_app_info == nullptr) {
        if (pm_app_info != nullptr) env->DeleteLocalRef(pm_app_info);
        env->DeleteLocalRef(package_name);
        env->DeleteLocalRef(package_manager_class);
        env->DeleteLocalRef(context_app_info);
        env->DeleteLocalRef(package_manager);
        env->DeleteLocalRef(data_dir);
        env->DeleteLocalRef(files_dir);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageManager 路径读取失败";
        return false;
    }
    success = CopyStringField(env, pm_app_info, "sourceDir",
                              paths.package_manager_source_path, error,
                              "PackageManager sourceDir") &&
              CopyStringField(env, pm_app_info, "publicSourceDir",
                              paths.package_manager_public_source_path, error,
                              "PackageManager publicSourceDir") &&
              CopyStringField(env, pm_app_info, "dataDir",
                              paths.package_manager_data_path, error,
                              "PackageManager dataDir");

    env->DeleteLocalRef(pm_app_info);
    env->DeleteLocalRef(package_name);
    env->DeleteLocalRef(package_manager_class);
    env->DeleteLocalRef(context_app_info);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(data_dir);
    env->DeleteLocalRef(files_dir);
    env->DeleteLocalRef(context_class);
    return success;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

bool SameFilesystemObject(const std::string& left, const std::string& right) {
    struct stat left_stat{};
    struct stat right_stat{};
    return stat(left.c_str(), &left_stat) == 0 &&
           stat(right.c_str(), &right_stat) == 0 &&
           left_stat.st_dev == right_stat.st_dev &&
           left_stat.st_ino == right_stat.st_ino &&
           (left_stat.st_mode & S_IFMT) == (right_stat.st_mode & S_IFMT);
}

bool ValidateAndroidAppPaths(const AndroidAppPaths& paths, std::string& error) {
    if (paths.package_name != kExpectedPackageName) {
        error = "应用包名身份不匹配";
        return false;
    }
    const std::array<std::string_view, 6> apk_paths{
            paths.code_path, paths.resource_path, paths.context_source_path,
            paths.context_public_source_path, paths.package_manager_source_path,
            paths.package_manager_public_source_path};
    if (apk_paths[0].empty() ||
        std::any_of(apk_paths.begin(), apk_paths.end(), [&](std::string_view path) {
            return path.empty() || path != apk_paths[0];
        })) {
        error = "APK 路径身份不一致";
        return false;
    }
    const std::string package_suffix = "/" + paths.package_name;
    const std::string files_suffix = package_suffix + "/files";
    if (paths.data_path.empty() || paths.package_manager_data_path.empty() ||
        paths.files_path.empty() || !EndsWith(paths.data_path, package_suffix) ||
        !EndsWith(paths.package_manager_data_path, package_suffix) ||
        !EndsWith(paths.files_path, files_suffix) ||
        !SameFilesystemObject(paths.data_path, paths.package_manager_data_path) ||
        !SameFilesystemObject(paths.files_path, paths.data_path + "/files") ||
        !SameFilesystemObject(paths.files_path, paths.package_manager_data_path + "/files")) {
        LOGE("data path mismatch: context='{}' package-manager='{}' files='{}'",
             paths.data_path, paths.package_manager_data_path, paths.files_path);
        error = "应用数据目录身份不一致";
        return false;
    }
    return true;
}

bool EqualTimespec(const timespec& left, const timespec& right) {
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

bool EqualStat(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_nlink == right.st_nlink &&
           left.st_uid == right.st_uid && left.st_gid == right.st_gid &&
           left.st_rdev == right.st_rdev && left.st_size == right.st_size &&
           left.st_blksize == right.st_blksize && left.st_blocks == right.st_blocks &&
           EqualTimespec(left.st_atim, right.st_atim) &&
           EqualTimespec(left.st_mtim, right.st_mtim) &&
           EqualTimespec(left.st_ctim, right.st_ctim);
}

bool EqualStableStat(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_nlink == right.st_nlink &&
           left.st_uid == right.st_uid && left.st_gid == right.st_gid &&
           left.st_rdev == right.st_rdev && left.st_size == right.st_size &&
           left.st_blksize == right.st_blksize && left.st_blocks == right.st_blocks &&
           EqualTimespec(left.st_mtim, right.st_mtim) &&
           EqualTimespec(left.st_ctim, right.st_ctim);
}

bool ValidateDataDirectory(const AndroidAppPaths& paths, std::string& error) {
    int data_fd = open(paths.data_path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (data_fd < 0) {
        error = "应用数据目录不可访问";
        return false;
    }
    struct stat data_stat{};
    struct stat files_stat{};
    const bool valid = fstat(data_fd, &data_stat) == 0 && S_ISDIR(data_stat.st_mode) &&
                       stat(paths.files_path.c_str(), &files_stat) == 0 &&
                       S_ISDIR(files_stat.st_mode) && data_stat.st_uid == getuid() &&
                       files_stat.st_uid == getuid();
    close(data_fd);
    if (!valid) {
        error = "应用私有目录属性异常";
        return false;
    }

    if (paths.data_path.starts_with("/data/user/0/") ||
        paths.package_manager_data_path.starts_with("/data/user/0/")) {
        const std::string legacy_path = "/data/data/" + paths.package_name;
        struct stat legacy_stat{};
        if (stat(legacy_path.c_str(), &legacy_stat) != 0 ||
            legacy_stat.st_dev != data_stat.st_dev || legacy_stat.st_ino != data_stat.st_ino) {
            error = "应用私有目录映射不一致";
            return false;
        }
    }
    return true;
}

bool ReadFullyAt(int fd, uint64_t offset, void* output, size_t size) {
    if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) return false;
    auto* bytes = static_cast<uint8_t*>(output);
    size_t completed = 0;
    while (completed < size) {
        const uint64_t current = offset + completed;
        if (current > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) return false;
        const ssize_t count = pread(fd, bytes + completed, size - completed,
                                    static_cast<off_t>(current));
        if (count == 0) return false;
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        completed += static_cast<size_t>(count);
    }
    return true;
}

uint16_t ReadLe16(const uint8_t* bytes) {
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8u);
}

uint32_t ReadLe32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8u) |
           (static_cast<uint32_t>(bytes[2]) << 16u) |
           (static_cast<uint32_t>(bytes[3]) << 24u);
}

uint64_t ReadLe64(const uint8_t* bytes) {
    return static_cast<uint64_t>(ReadLe32(bytes)) |
           (static_cast<uint64_t>(ReadLe32(bytes + 4)) << 32u);
}

class ByteCursor {
public:
    ByteCursor() = default;
    ByteCursor(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool ReadLengthPrefixed(ByteCursor& value) {
        if (Remaining() < sizeof(uint32_t)) return false;
        const uint32_t length = ReadLe32(data_ + position_);
        position_ += sizeof(uint32_t);
        if (length > Remaining()) return false;
        value = ByteCursor(data_ + position_, length);
        position_ += length;
        return true;
    }

    size_t Remaining() const { return size_ - position_; }
    const uint8_t* Data() const { return data_ + position_; }
    size_t Size() const { return size_; }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t position_ = 0;
};

bool ParseV2SignerCertificate(const std::vector<uint8_t>& v2_block,
                              std::vector<uint8_t>& certificate,
                              std::string& error) {
    ByteCursor block(v2_block.data(), v2_block.size());
    ByteCursor signers;
    ByteCursor signer;
    ByteCursor signed_data;
    ByteCursor signatures;
    ByteCursor public_key;
    if (!block.ReadLengthPrefixed(signers) || block.Remaining() != 0 ||
        !signers.ReadLengthPrefixed(signer) || signers.Remaining() != 0 ||
        !signer.ReadLengthPrefixed(signed_data) ||
        !signer.ReadLengthPrefixed(signatures) ||
        !signer.ReadLengthPrefixed(public_key) || signer.Remaining() != 0) {
        error = "APK v2 signer 结构无效";
        return false;
    }

    ByteCursor digests;
    ByteCursor certificates;
    if (!signed_data.ReadLengthPrefixed(digests) ||
        !signed_data.ReadLengthPrefixed(certificates)) {
        error = "APK v2 signed-data 结构无效";
        return false;
    }

    // Additional attributes are signed but vendor/toolchain versions may append
    // opaque data after the standard sequence. They are not needed to identify
    // the certificate; keep the bounds check without requiring a byte-for-byte
    // layout that differs across valid APK producers.
    if (signed_data.Remaining() != 0) {
        LOGD("APK v2 signed-data has {} opaque trailing bytes", signed_data.Remaining());
    }

    ByteCursor first_certificate;
    if (!certificates.ReadLengthPrefixed(first_certificate) ||
        first_certificate.Size() == 0 || first_certificate.Size() > 1024u * 1024u) {
        error = "APK v2 证书序列无效";
        return false;
    }
    certificate.assign(first_certificate.Data(),
                       first_certificate.Data() + first_certificate.Size());

    while (certificates.Remaining() != 0) {
        ByteCursor ignored_certificate;
        if (!certificates.ReadLengthPrefixed(ignored_certificate) ||
            ignored_certificate.Size() == 0) {
            error = "APK v2 证书链结构无效";
            return false;
        }
    }
    return true;
}

bool ExtractV2SignerCertificate(int fd, const struct stat& apk_stat,
                                std::vector<uint8_t>& certificate,
                                std::string& error) {
    if (apk_stat.st_size < static_cast<off_t>(kZipEocdSize)) {
        error = "APK ZIP 结构过短";
        return false;
    }
    const uint64_t file_size = static_cast<uint64_t>(apk_stat.st_size);
    const size_t tail_size = static_cast<size_t>(std::min<uint64_t>(
            file_size, kZipEocdSize + kMaxZipCommentSize));
    std::vector<uint8_t> tail(tail_size);
    if (!ReadFullyAt(fd, file_size - tail_size, tail.data(), tail.size())) {
        error = "APK EOCD 读取失败";
        return false;
    }

    size_t eocd_in_tail = std::numeric_limits<size_t>::max();
    for (size_t candidate = tail.size() - kZipEocdSize + 1; candidate-- > 0;) {
        if (ReadLe32(tail.data() + candidate) != kZipEocdSignature) continue;
        const uint16_t comment_size = ReadLe16(tail.data() + candidate + 20);
        if (candidate + kZipEocdSize + comment_size == tail.size()) {
            eocd_in_tail = candidate;
            break;
        }
    }
    if (eocd_in_tail == std::numeric_limits<size_t>::max()) {
        error = "APK EOCD 不可用";
        return false;
    }

    const uint8_t* eocd = tail.data() + eocd_in_tail;
    const uint16_t disk_number = ReadLe16(eocd + 4);
    const uint16_t directory_disk = ReadLe16(eocd + 6);
    const uint16_t entries_on_disk = ReadLe16(eocd + 8);
    const uint16_t total_entries = ReadLe16(eocd + 10);
    const uint32_t directory_size = ReadLe32(eocd + 12);
    const uint32_t directory_offset = ReadLe32(eocd + 16);
    const uint64_t eocd_offset = file_size - tail_size + eocd_in_tail;
    if (disk_number != 0 || directory_disk != 0 || entries_on_disk != total_entries ||
        entries_on_disk == 0xffff || directory_size == 0xffffffffu ||
        directory_offset == 0xffffffffu ||
        static_cast<uint64_t>(directory_offset) + directory_size != eocd_offset) {
        error = "APK ZIP64 或多磁盘布局不受支持";
        return false;
    }
    if (directory_offset < 24) {
        error = "APK Signing Block footer 缺失";
        return false;
    }

    std::array<uint8_t, 24> footer{};
    if (!ReadFullyAt(fd, static_cast<uint64_t>(directory_offset) - footer.size(),
                     footer.data(), footer.size()) ||
        memcmp(footer.data() + 8, kApkSigningBlockMagic, 16) != 0) {
        error = "APK Signing Block magic 不匹配";
        return false;
    }
    const uint64_t block_size = ReadLe64(footer.data());
    if (block_size < 24 || block_size > kMaxSigningBlockSize ||
        block_size + 8 > directory_offset) {
        error = "APK Signing Block 大小无效";
        return false;
    }
    const uint64_t block_start = static_cast<uint64_t>(directory_offset) - block_size - 8;
    std::array<uint8_t, 8> leading_size{};
    if (!ReadFullyAt(fd, block_start, leading_size.data(), leading_size.size()) ||
        ReadLe64(leading_size.data()) != block_size) {
        error = "APK Signing Block 双端大小不一致";
        return false;
    }

    const uint64_t pairs_end = static_cast<uint64_t>(directory_offset) - footer.size();
    uint64_t cursor = block_start + leading_size.size();
    bool found_v2 = false;
    std::vector<uint8_t> v2_block;
    while (cursor < pairs_end) {
        std::array<uint8_t, 12> pair_header{};
        if (pairs_end - cursor < pair_header.size() ||
            !ReadFullyAt(fd, cursor, pair_header.data(), pair_header.size())) {
            error = "APK Signing Block 条目截断";
            return false;
        }
        const uint64_t pair_size = ReadLe64(pair_header.data());
        const uint32_t pair_id = ReadLe32(pair_header.data() + 8);
        if (pair_size < sizeof(uint32_t) || pair_size > pairs_end - cursor - sizeof(uint64_t)) {
            error = "APK Signing Block 条目大小无效";
            return false;
        }
        const uint64_t value_size = pair_size - sizeof(uint32_t);
        if (pair_id == kApkSignatureSchemeV2Id) {
            if (found_v2 || value_size == 0 || value_size > kMaxSigningBlockSize) {
                error = "APK v2 签名块重复或大小无效";
                return false;
            }
            v2_block.resize(static_cast<size_t>(value_size));
            if (!ReadFullyAt(fd, cursor + pair_header.size(),
                             v2_block.data(), v2_block.size())) {
                error = "APK v2 签名块读取失败";
                return false;
            }
            found_v2 = true;
        }
        cursor += sizeof(uint64_t) + pair_size;
    }
    if (cursor != pairs_end || !found_v2) {
        error = found_v2 ? "APK Signing Block 边界无效" : "APK v2 签名块缺失";
        return false;
    }
    return ParseV2SignerCertificate(v2_block, certificate, error);
}

bool ReadPackageManagerSigner(JNIEnv* env, jobject context,
                              std::vector<uint8_t>& certificate,
                              std::string& error) {
    jclass context_class = env->GetObjectClass(context);
    if (context_class == nullptr || ConsumeJniException(env, error, "Context 类型不可用")) {
        if (error.empty()) error = "Context 类型不可用";
        return false;
    }
    jmethodID get_package_manager = env->GetMethodID(
            context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID get_package_name = env->GetMethodID(
            context_class, "getPackageName", "()Ljava/lang/String;");
    if (get_package_manager == nullptr || get_package_name == nullptr ||
        ConsumeJniException(env, error, "PackageManager 签名接口不可用")) {
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageManager 签名接口不可用";
        return false;
    }
    jobject package_manager = env->CallObjectMethod(context, get_package_manager);
    auto package_name = static_cast<jstring>(env->CallObjectMethod(context, get_package_name));
    if (ConsumeJniException(env, error, "PackageManager 签名上下文读取异常") ||
        package_manager == nullptr || package_name == nullptr) {
        if (package_manager != nullptr) env->DeleteLocalRef(package_manager);
        if (package_name != nullptr) env->DeleteLocalRef(package_name);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageManager 签名上下文读取失败";
        return false;
    }

    jclass package_manager_class = env->GetObjectClass(package_manager);
    jmethodID get_package_info = package_manager_class == nullptr ? nullptr : env->GetMethodID(
            package_manager_class, "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (get_package_info == nullptr ||
        ConsumeJniException(env, error, "PackageInfo 签名接口不可用")) {
        if (package_manager_class != nullptr) env->DeleteLocalRef(package_manager_class);
        env->DeleteLocalRef(package_manager);
        env->DeleteLocalRef(package_name);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageInfo 签名接口不可用";
        return false;
    }

    constexpr jint kGetSignatures = 0x00000040;
    constexpr jint kGetSigningCertificates = 0x08000000;
    const bool modern_signing = GetAndroidApiLevel() >= 28;
    jobject package_info = env->CallObjectMethod(
            package_manager, get_package_info, package_name,
            modern_signing ? kGetSigningCertificates : kGetSignatures);
    if (ConsumeJniException(env, error, "PackageInfo 签名读取异常") || package_info == nullptr) {
        if (package_info != nullptr) env->DeleteLocalRef(package_info);
        env->DeleteLocalRef(package_manager_class);
        env->DeleteLocalRef(package_manager);
        env->DeleteLocalRef(package_name);
        env->DeleteLocalRef(context_class);
        if (error.empty()) error = "PackageInfo 签名读取失败";
        return false;
    }

    jclass package_info_class = env->GetObjectClass(package_info);
    jobjectArray signatures = nullptr;
    jobject signing_info = nullptr;
    if (modern_signing) {
        jfieldID signing_info_field = package_info_class == nullptr ? nullptr : env->GetFieldID(
                package_info_class, "signingInfo", "Landroid/content/pm/SigningInfo;");
        if (signing_info_field != nullptr) {
            signing_info = env->GetObjectField(package_info, signing_info_field);
        }
        jclass signing_info_class = signing_info == nullptr ? nullptr : env->GetObjectClass(signing_info);
        jmethodID get_signers = signing_info_class == nullptr ? nullptr : env->GetMethodID(
                signing_info_class, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
        if (get_signers != nullptr) {
            signatures = static_cast<jobjectArray>(env->CallObjectMethod(signing_info, get_signers));
        }
        if (signing_info_class != nullptr) env->DeleteLocalRef(signing_info_class);
    } else {
        jfieldID signatures_field = package_info_class == nullptr ? nullptr : env->GetFieldID(
                package_info_class, "signatures", "[Landroid/content/pm/Signature;");
        if (signatures_field != nullptr) {
            signatures = static_cast<jobjectArray>(env->GetObjectField(package_info, signatures_field));
        }
    }

    bool success = !ConsumeJniException(env, error, "PackageManager signer 读取异常") &&
                   signatures != nullptr && env->GetArrayLength(signatures) == 1;
    if (!success && error.empty()) error = "PackageManager signer 数量异常";
    jobject signature = success ? env->GetObjectArrayElement(signatures, 0) : nullptr;
    jclass signature_class = signature == nullptr ? nullptr : env->GetObjectClass(signature);
    jmethodID to_byte_array = signature_class == nullptr ? nullptr : env->GetMethodID(
            signature_class, "toByteArray", "()[B");
    auto bytes = to_byte_array == nullptr ? nullptr : static_cast<jbyteArray>(
            env->CallObjectMethod(signature, to_byte_array));
    if (ConsumeJniException(env, error, "PackageManager signer 编码异常") || bytes == nullptr) {
        success = false;
        if (error.empty()) error = "PackageManager signer 编码失败";
    }
    if (success) {
        const jsize size = env->GetArrayLength(bytes);
        if (size <= 0) {
            success = false;
            error = "PackageManager signer 证书为空";
        } else {
            certificate.resize(static_cast<size_t>(size));
            env->GetByteArrayRegion(bytes, 0, size,
                                    reinterpret_cast<jbyte*>(certificate.data()));
            if (ConsumeJniException(env, error, "PackageManager signer 复制异常")) {
                success = false;
            }
        }
    }

    if (bytes != nullptr) env->DeleteLocalRef(bytes);
    if (signature_class != nullptr) env->DeleteLocalRef(signature_class);
    if (signature != nullptr) env->DeleteLocalRef(signature);
    if (signatures != nullptr) env->DeleteLocalRef(signatures);
    if (signing_info != nullptr) env->DeleteLocalRef(signing_info);
    if (package_info_class != nullptr) env->DeleteLocalRef(package_info_class);
    env->DeleteLocalRef(package_info);
    env->DeleteLocalRef(package_manager_class);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(package_name);
    env->DeleteLocalRef(context_class);
    return success;
}

bool ValidateApkMapIdentity(const std::string& apk_path, const struct stat& apk_stat,
                            std::string& error) {
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        error = "进程 maps 不可读取";
        return false;
    }
    char* line = nullptr;
    size_t capacity = 0;
    bool found = false;
    bool mismatch = false;
    while (getline(&line, &capacity, maps) >= 0) {
        unsigned int device_major = 0;
        unsigned int device_minor = 0;
        unsigned long long inode = 0;
        int path_offset = 0;
        if (sscanf(line, "%*s %*s %*s %x:%x %llu %n",
                   &device_major, &device_minor, &inode, &path_offset) != 3 ||
            path_offset <= 0) {
            continue;
        }
        std::string_view mapped_path(line + path_offset);
        while (!mapped_path.empty() && mapped_path.front() == ' ') mapped_path.remove_prefix(1);
        while (!mapped_path.empty() &&
               (mapped_path.back() == '\n' || mapped_path.back() == '\r')) {
            mapped_path.remove_suffix(1);
        }
        if (mapped_path != apk_path) continue;
        found = true;
        if (inode != static_cast<unsigned long long>(apk_stat.st_ino) ||
            device_major != static_cast<unsigned int>(major(apk_stat.st_dev)) ||
            device_minor != static_cast<unsigned int>(minor(apk_stat.st_dev))) {
            mismatch = true;
            break;
        }
    }
    free(line);
    fclose(maps);
    if (!found) {
        error = "APK 未出现在进程文件映射中";
        return false;
    }
    if (mismatch) {
        error = "APK maps inode 身份不匹配";
        return false;
    }
    return true;
}

}  // namespace

std::array<uint8_t, 32> ComputeSha256(std::string_view data) {
    return Sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool VerifyInstalledApkIdentity(JNIEnv* env, jobject context, std::string& error) {
    error.clear();
    AndroidAppPaths paths;
    if (!CollectAndroidAppPaths(env, context, paths, error) ||
        !ValidateAndroidAppPaths(paths, error) ||
        !ValidateDataDirectory(paths, error)) {
        LOGE("APK identity path check failed: {}", error);
        return false;
    }

    const std::string& apk_path = paths.code_path;
    int apk_fd = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (apk_fd < 0) {
        error = "APK 文件不可打开";
        PLOGE("failed to open APK {}", apk_path);
        return false;
    }

    char fd_path_buffer[PATH_MAX + 1]{};
    const std::string fd_link = "/proc/self/fd/" + std::to_string(apk_fd);
    const ssize_t fd_path_size = readlink(fd_link.c_str(), fd_path_buffer, PATH_MAX);
    if (fd_path_size < 0) {
        close(apk_fd);
        error = "APK fd 路径不可读取";
        return false;
    }
    fd_path_buffer[fd_path_size] = '\0';
    if (static_cast<size_t>(fd_path_size) != apk_path.size() ||
        memcmp(fd_path_buffer, apk_path.data(), apk_path.size()) != 0) {
        close(apk_fd);
        error = "APK fd 路径身份不匹配";
        return false;
    }

    struct stat fd_stat_before{};
    struct stat path_stat_before{};
    if (fstat(apk_fd, &fd_stat_before) != 0 || stat(apk_path.c_str(), &path_stat_before) != 0 ||
        !EqualStat(fd_stat_before, path_stat_before) || !S_ISREG(fd_stat_before.st_mode) ||
        fd_stat_before.st_size <= 0 || fd_stat_before.st_nlink == 0 ||
        (fd_stat_before.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(apk_fd);
        error = "APK 文件元数据身份不匹配";
        return false;
    }
    if (apk_path.starts_with("/data/app/") &&
        (fd_stat_before.st_uid != 1000 || fd_stat_before.st_gid != 1000)) {
        close(apk_fd);
        error = "APK 文件所有者异常";
        return false;
    }
    if (!ValidateApkMapIdentity(apk_path, fd_stat_before, error)) {
        close(apk_fd);
        return false;
    }

    std::vector<uint8_t> package_manager_certificate;
    std::vector<uint8_t> signing_block_certificate;
    if (!ReadPackageManagerSigner(env, context, package_manager_certificate, error) ||
        !ExtractV2SignerCertificate(apk_fd, fd_stat_before, signing_block_certificate, error)) {
        close(apk_fd);
        LOGE("APK signer extraction failed: {}", error);
        return false;
    }

    struct stat fd_stat_after{};
    struct stat path_stat_after{};
    if (fstat(apk_fd, &fd_stat_after) != 0 || stat(apk_path.c_str(), &path_stat_after) != 0 ||
        !EqualStat(fd_stat_after, path_stat_after) ||
        !EqualStableStat(fd_stat_before, fd_stat_after)) {
        close(apk_fd);
        error = "APK 校验期间文件身份发生变化";
        return false;
    }
    close(apk_fd);

    std::array<uint8_t, 32> expected_digest{};
    if (!DecodeHexDigest(APP_SIGNER_SHA256, expected_digest)) {
        error = "内置 APK signer 摘要无效";
        return false;
    }
    const auto package_manager_digest = Sha256(
            package_manager_certificate.data(), package_manager_certificate.size());
    const auto signing_block_digest = Sha256(
            signing_block_certificate.data(), signing_block_certificate.size());
    if (!ConstantTimeEqual(package_manager_digest, expected_digest) ||
        !ConstantTimeEqual(signing_block_digest, expected_digest)) {
        error = "APK signer 证书与项目签名不匹配";
        LOGE("APK signer certificate mismatch");
        return false;
    }
    if (package_manager_certificate != signing_block_certificate) {
        error = "PackageManager 与 APK Signing Block signer 不一致";
        return false;
    }

    app_apk_path = apk_path;
    LOGI("APK identity verified through path, inode, maps and pinned v2 signer");
    return true;
}

bool VerifyApkSignatureStructure(JNIEnv* env, std::string& error) {
    auto verifier_class = FindClassFromLoader(
            env, sDexClassLoader, "com/lingqing/trustattestor/Verifier");
    if (verifier_class == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        error = "未找到 Verifier";
        return false;
    }
    jmethodID verifier_method = env->GetStaticMethodID(
            verifier_class, "run", "(Ljava/lang/String;)Z");
    if (verifier_method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(verifier_class);
        error = "Verifier.run 方法获取失败";
        return false;
    }
    jstring apk_path = env->NewStringUTF(app_apk_path.c_str());
    if (apk_path == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(verifier_class);
        error = "APK 路径转换失败";
        return false;
    }
    const jboolean verified = env->CallStaticBooleanMethod(
            verifier_class, verifier_method, apk_path);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(apk_path);
        env->DeleteLocalRef(verifier_class);
        error = "APK 签名结构校验调用失败";
        return false;
    }
    env->DeleteLocalRef(apk_path);
    env->DeleteLocalRef(verifier_class);
    if (verified != JNI_TRUE) {
        error = "APK 签名结构校验失败";
        return false;
    }
    return true;
}

bool ApplyKeyAttestationResult(jint check) {
    if (check < 0) return false;
    if (check == 0) {
        LOGE("Key attestation failed");
        MarkConventional(1u << 3);
    }
    if ((check & 2) != 0) {
        LOGE("Key attestation did not complete");
        MarkProbeUnavailable(2, "hardware.attestation.flow_incomplete");
    }
    if ((check & 64) != 0) {
        LOGE("Key attestation tampering found");
        MarkConventional(1u << 3);
        MarkAbnormalKey(1);
    }
    if ((check & 8) != 0) {
        LOGE("AOSP key found");
        MarkConventional(1u << 3);
        MarkAbnormalKey(2);
    }
    if ((check & 16) != 0) {
        LOGE("Unknown key found");
        MarkConventional(1u << 3);
        MarkAbnormalKey(4);
    }
    if ((check & 32) != 0) {
        // Legacy Java result bit. New builds publish VBMeta/RootOfTrust mismatches
        // through detailed probe flags, but keep the old channel correctly mapped.
        LOGE("Legacy RootOfTrust or VBMeta consistency mismatch found");
        MarkConventional(1u << 3);
        MarkAbnormalKey(16);
    }
    if (check & 4) {
        MarkProbeUnavailable(2, "hardware.attestation.verification");
    }
    return true;
}

namespace {

jlong TimingClockValue(bool resolution) {
    timespec value{};
    const int status = resolution ? clock_getres(CLOCK_MONOTONIC_RAW, &value)
                                  : clock_gettime(CLOCK_MONOTONIC_RAW, &value);
    constexpr jlong billion = 1000000000LL;
    if (status != 0 || value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= billion ||
        static_cast<uint64_t>(value.tv_sec) >
            static_cast<uint64_t>((std::numeric_limits<jlong>::max() - value.tv_nsec) / billion)) {
        return -1;
    }
    return static_cast<jlong>(value.tv_sec) * billion + value.tv_nsec;
}

jlong ReadTimingClock(JNIEnv *, jclass) { return TimingClockValue(false); }
jlong ReadTimingResolution(JNIEnv *, jclass) { return TimingClockValue(true); }

void RegisterTimingClock(JNIEnv *env) {
    auto clazz = FindClassFromLoader(env, sDexClassLoader,
                                    "com/lingqing/trustattestor/KeystoreTimingClock");
    if (clazz != nullptr && !env->ExceptionCheck()) {
        const JNINativeMethod methods[] = {
                {const_cast<char *>("nativeClockNanos"), const_cast<char *>("()J"),
                 reinterpret_cast<void *>(ReadTimingClock)},
                {const_cast<char *>("nativeClockResolutionNanos"), const_cast<char *>("()J"),
                 reinterpret_cast<void *>(ReadTimingResolution)},
        };
        env->RegisterNatives(clazz, methods, 2);
    }
    // The Java session selects its fixed fallback before collecting any samples.
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (clazz != nullptr) env->DeleteLocalRef(clazz);
}

bool IsKnownKeystoreUnavailableProbe(std::string_view id) {
    static constexpr std::array<std::string_view, 41> kKnown{
            "hardware.attestation.attest_key_descriptor_delegation.unavailable",
            "hardware.attestation.metadata_security_level.unavailable",
            "hardware.attestation.binder_locality.unavailable",
            "hardware.attestation.interface_token_dispatch.unavailable",
            "hardware.attestation.parameter_fingerprint.unavailable",
            "hardware.attestation.teesim_parameter_fingerprint.unavailable",
            "hardware.attestation.reply_lag.unavailable",
            "hardware.attestation.read_path_timing.unavailable",
            "hardware.attestation.key_id_consistency.unavailable",
            "hardware.attestation.keystore_ledger.unavailable",
            "hardware.attestation.cross_sign.unavailable",
            "hardware.attestation.certificate_graph.unavailable",
            "hardware.attestation.trap_probe.unavailable",
            "hardware.attestation.keystore_state_machine.unavailable",
            "hardware.attestation.alias_cross_talk.unavailable",
            "hardware.attestation.challenge_replay.unavailable",
            "hardware.attestation.null_challenge.unavailable",
            "hardware.attestation.negative_probe.unavailable",
            "hardware.attestation.leaf_constraints.unavailable",
            "hardware.attestation.application_id.unavailable",
            "hardware.attestation.key_metadata.unavailable",
            "hardware.attestation.imported_key.unavailable",
            "hardware.attestation.patch_level.unavailable",
            "hardware.attestation.user_auth_policy.unavailable",
            "hardware.attestation.single_use_policy.unavailable",
            "hardware.attestation.future_validity_policy.unavailable",
            "hardware.attestation.unique_id_permission.unavailable",
            "hardware.attestation.user_auth_metadata.unavailable",
            "hardware.attestation.signing_lineage.unavailable",
            "hardware.attestation.operation_semantics.unavailable",
            "hardware.attestation.device_properties.unavailable",
            "hardware.attestation.algorithm_differential.unavailable",
            "hardware.attestation.strongbox_differential.unavailable",
            "hardware.attestation.keymint_boundary.unavailable",
            "hardware.attestation.rsa_conformance.unavailable",
            "hardware.attestation.hmac_conformance.unavailable",
            "hardware.attestation.ecdh_conformance.unavailable",
            "hardware.attestation.aes_conformance.unavailable",
            "hardware.attestation.entry_semantics.unavailable",
            "hardware.attestation.main_binding.unavailable",
            "hardware.attestation.operation_isolation.unavailable",
    };
    return std::find(kKnown.begin(), kKnown.end(), id) != kKnown.end();
}

}  // namespace

void PrepareKeystoreTimingClock(JNIEnv *env) {
    RegisterTimingClock(env);
}

void CollectKeystoreProbeStatus(JNIEnv *env, jclass key_attestation_class) {
    jint isolated_status = 7;
    auto isolated_method = env->GetStaticMethodID(
            key_attestation_class, "getLastIsolatedChainStatus", "()I");
    if (isolated_method != nullptr && !env->ExceptionCheck()) {
        isolated_status = env->CallStaticIntMethod(key_attestation_class, isolated_method);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        isolated_status = 7;
    }
    switch (isolated_status) {
        case 0: case 1: case 2: break;
        case 3: MarkProbeUnavailable(2, "hardware.attestation.isolated_chain.access_unavailable"); break;
        case 4: MarkProbeUnavailable(2, "hardware.attestation.isolated_chain.transport_unavailable"); break;
        case 5: MarkProbeUnavailable(2, "hardware.attestation.isolated_chain.evidence_unavailable"); break;
        case 6: MarkProbeUnavailable(2, "hardware.attestation.isolated_chain.cleanup_incomplete"); break;
        default: MarkProbeUnavailable(2, "hardware.attestation.isolated_chain.not_run"); break;
    }

    jint states = 15;
    auto method = env->GetStaticMethodID(key_attestation_class, "getLastCertificateRecordStatus", "()I");
    if (method != nullptr && !env->ExceptionCheck()) {
        states = env->CallStaticIntMethod(key_attestation_class, method);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        states = 15;
    }
    if (states < 0 || states > 15) states = 15;
    if ((states & 3) >= 2) {
        MarkProbeUnavailable(2, "hardware.attestation.chain_read_stability.unavailable");
    }
    if (((states >> 2) & 3) >= 2) {
        MarkProbeUnavailable(2, "hardware.attestation.certificate_round_trip.unavailable");
    }
    jint timing = 3;
    auto timing_method = env->GetStaticMethodID(key_attestation_class, "getLastTimingProbeStatus", "()I");
    if (timing_method != nullptr && !env->ExceptionCheck()) {
        timing = env->CallStaticIntMethod(key_attestation_class, timing_method);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        timing = 3;
    }
    if (timing < 0 || timing > 1) {
        MarkProbeUnavailable(2, "hardware.attestation.keystore_timing.unavailable");
    }

    auto unavailable_method = env->GetStaticMethodID(
            key_attestation_class, "getLastUnavailableProbeIds", "()[Ljava/lang/String;");
    if (unavailable_method == nullptr || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        MarkProbeUnavailable(2, "hardware.attestation.probe_status.unavailable");
        return;
    }
    auto unavailable = static_cast<jobjectArray>(
            env->CallStaticObjectMethod(key_attestation_class, unavailable_method));
    if (env->ExceptionCheck() || unavailable == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        MarkProbeUnavailable(2, "hardware.attestation.probe_status.unavailable");
        if (unavailable != nullptr) env->DeleteLocalRef(unavailable);
        return;
    }
    const jsize count = std::min<jsize>(env->GetArrayLength(unavailable), 64);
    for (jsize i = 0; i < count; ++i) {
        auto value = static_cast<jstring>(env->GetObjectArrayElement(unavailable, i));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            continue;
        }
        if (value == nullptr) continue;
        const char *chars = env->GetStringUTFChars(value, nullptr);
        if (chars != nullptr) {
            std::string_view id(chars);
            if (IsKnownKeystoreUnavailableProbe(id)) {
                MarkProbeUnavailable(2, id);
            }
            env->ReleaseStringUTFChars(value, chars);
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(unavailable);
}

RINLINE bool KeyAttestation(JNIEnv *env, jobject context) {
    auto my_class = FindClassFromLoader(env, sDexClassLoader, "com/lingqing/trustattestor/KeyAttestation");
    if (my_class == nullptr) return false;
    auto my_method = env->GetStaticMethodID(my_class, "run", "(Landroid/content/Context;)I");
    if (my_method == nullptr) {
        env->DeleteLocalRef(my_class);
        return false;
    }
    PrepareKeystoreTimingClock(env);
    jint check = env->CallStaticIntMethod(my_class, my_method, context);
    if (!env->ExceptionCheck()) {
        auto flags_method = env->GetStaticMethodID(my_class, "getLastProbeFlags", "()J");
        if (flags_method != nullptr && !env->ExceptionCheck()) {
            auto flags = static_cast<uint64_t>(env->CallStaticLongMethod(my_class, flags_method));
            if (!env->ExceptionCheck()) MarkKeyAttestationFlags(flags);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!env->ExceptionCheck()) CollectKeystoreProbeStatus(env, my_class);
    env->DeleteLocalRef(my_class);
    LOGD("KeyAttestation {}", check);
    return ApplyKeyAttestationResult(check);
}

enum CheckResult {
    ERROR,
    TRUE,
    FALSE
};

constexpr const auto kDoApAuthBranch = 0x8000000000001008;
constexpr const auto kNoApAuthBranch = 0x8000000000000000;

RINLINE CheckResult CheckTruncateMincore(uint64_t len) {
    auto addr = mmap(nullptr, getpagesize(), PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (addr == reinterpret_cast<void*>(-1)) {
        PLOGE("failed to mmap");
        return ERROR;
    }
    unsigned char ch = 0;
    if (mincore(addr, getpagesize(), &ch) == -1) {
        PLOGE("failed to mincore");
        munmap(addr, getpagesize());
        return ERROR;
    }
    LOGD("ch = {}", ch);
    if (ch != 0) {
        munmap(addr, getpagesize());
        return ERROR;
    }
    auto result_ = syscall(45, addr, len);
    LOGD("return {} errno {}", result_, errno);
    ch = 0;
    if (mincore(addr, getpagesize(), &ch) == -1) {
        PLOGE("failed to mincore");
        munmap(addr, getpagesize());
        return ERROR;
    }
    LOGD("ch = {}", ch);
    munmap(addr, getpagesize());
    return ch == 0 ? FALSE : TRUE;
}

void FindAPatch() {
    bool has_ap = false;

    // check mincore
    struct utsname uts{};
    if (uname(&uts) == 0 && uts.release[0] - '0' <= 4) {
        auto no_ap_pagefault = CheckTruncateMincore(kNoApAuthBranch);
        auto ap_pagefault = CheckTruncateMincore(kDoApAuthBranch);
        LOGI("no_ap_pagefault={} ap_pagefault={}",
             no_ap_pagefault,
             ap_pagefault);
        if (no_ap_pagefault == ERROR || ap_pagefault == ERROR) {
            MarkProbeUnavailable(0, "device.apatch.page_fault");
        }
        has_ap |= no_ap_pagefault == FALSE && ap_pagefault == TRUE;
    }

    LOGI("has ap = {}", has_ap);

    if (has_ap) MarkAbnormalEnvironment();
}

RINLINE bool SupportStatx() {
    // Seccomp blocks statx
    if (GetAndroidApiLevel() < 30) return false;
    // No statx support for 4.11-
    struct statx stx{};
    if (syscall(SYS_statx, AT_FDCWD, "/TrustAttestor", AT_NO_AUTOMOUNT, STATX_BASIC_STATS, &stx) == -1 && errno == ENOSYS) {
        LOGE("Kernel has no statx support");
        return false;
    }
    return true;
}

std::unordered_set<unsigned> FindTrustedIncrementalPropagationGroups(
        const std::vector<proc_util::MountInfo>& mountlist);

unsigned IncrementalPropagationGroup(const proc_util::MountInfo& mount) {
    // In the global namespace IncFS mounts are normally shared mounts. After
    // zygote namespace propagation they may instead be visible as slaves of
    // that shared group. Both forms describe the same legitimate topology.
    return mount.optional.master != 0 ? mount.optional.master : mount.optional.shared;
}

RINLINE int FindMountidLoophole(std::vector<proc_util::MountInfo> mountlist, std::string_view mntbuf) {
    auto check_result = 0;
    const auto trusted_incfs_groups = FindTrustedIncrementalPropagationGroups(mountlist);
    // common assumption here: no umount during boot
    for (auto it = mountlist.begin(); it != mountlist.end(); ++it) {
        // dex2oat wrapper
        if (it->target == "/apex/com.android.art") {
            auto next_it = std::next(it);
            if (next_it != mountlist.end() && next_it->id > it->id + 1) {
                LOGE("FindMntidLoophole: expected id {}, but found {} for art", it->id + 1,
                     next_it->id);
                check_result |= APP_ZYGOTE_MOUNT_ART_GAP;
                continue;
            }
        }
        // last mount before zygote start, usually debug_ramdisk and other post-fs-data bind mounts
        if (it->target == mntbuf) {
            auto next_it = std::next(it);
            if (next_it != mountlist.end() && next_it->id > it->id + 1) {
                LOGE("FindMntidLoophole: expected id {}, but found {} for mntbuf '{}'", it->id + 1,
                     next_it->id, std::string(mntbuf));
                check_result |= APP_ZYGOTE_MOUNT_BOOT_GAP;
                continue;
            }
        }
        // very start of post-fs-data, usually modules.img
        if (it->target == "/data_mirror") {
            auto count = 0;
            auto current_id = it->id;
            auto has_gap = false;
            while (count < 10) {
                auto prev_id = current_id - 1;
                auto prev_it = std::find_if(mountlist.begin(), mountlist.end(),
                                            [&](const auto &entry) { return entry.id == prev_id; });
                if (prev_it == mountlist.end()) {
                    const auto current_it = std::find_if(
                            mountlist.begin(), mountlist.end(),
                            [&](const auto& entry) { return entry.id == current_id; });
                    const auto current_group = current_it == mountlist.end()
                            ? 0u : IncrementalPropagationGroup(*current_it);
                    if (current_it != mountlist.end() &&
                        trusted_incfs_groups.contains(current_group)) {
                        const auto peer_it = std::max_element(
                                mountlist.begin(), mountlist.end(),
                                [&](const auto& lhs, const auto& rhs) {
                                    const auto lhs_id = lhs.id < current_id &&
                                            IncrementalPropagationGroup(lhs) == current_group
                                            ? lhs.id : 0u;
                                    const auto rhs_id = rhs.id < current_id &&
                                            IncrementalPropagationGroup(rhs) == current_group
                                            ? rhs.id : 0u;
                                    return lhs_id < rhs_id;
                                });
                        if (peer_it != mountlist.end() && peer_it->id < current_id &&
                            IncrementalPropagationGroup(*peer_it) == current_group) {
                            LOGI("Ignore verified Incremental FS internal mount-id gap {}..{}",
                                 peer_it->id + 1, current_id - 1);
                            current_id = peer_it->id;
                            ++count;
                            continue;
                        }
                    }
                    LOGE("FindMntidLoophole: expected id {}, but cannot find it before data_mirror", prev_id);
                    has_gap = true;
                    break;
                }
                // stop at last mount of post-fs
                if (prev_it->target.starts_with("/data/user")) {
                    LOGI("Find /data/user target at id {}: {}", prev_it->id, prev_it->target);
                    break;
                }
                current_id = prev_id;
                count++;
            }
            if (has_gap) check_result |= APP_ZYGOTE_MOUNT_DATA_GAP;
        }
    }
    return check_result;
}

constexpr bool IsDecimalToken(std::string_view value) {
    return !value.empty() && std::ranges::all_of(value, [](char ch) {
        return ch >= '0' && ch <= '9';
    });
}

bool HasMountOption(std::string_view options, std::string_view expected) {
    size_t offset = 0;
    while (offset <= options.size()) {
        const auto separator = options.find(',', offset);
        const auto token = options.substr(
                offset,
                separator == std::string_view::npos ? std::string_view::npos : separator - offset);
        if (token == expected) return true;
        if (separator == std::string_view::npos) break;
        offset = separator + 1;
    }
    return false;
}

std::string_view MountOptionValue(std::string_view options, std::string_view key) {
    size_t offset = 0;
    while (offset <= options.size()) {
        const auto separator = options.find(',', offset);
        const auto token = options.substr(
                offset,
                separator == std::string_view::npos ? std::string_view::npos : separator - offset);
        if (token.starts_with(key)) return token.substr(key.size());
        if (separator == std::string_view::npos) break;
        offset = separator + 1;
    }
    return {};
}

bool IsDirectChildOf(std::string_view path, std::string_view directory) {
    if (!path.starts_with(directory) || path.size() <= directory.size()) return false;
    return path.find('/', directory.size()) == std::string_view::npos;
}

constexpr bool IsIncrementalStorageRoot(std::string_view root) {
    constexpr auto prefix = "/st_"sv;
    if (!root.starts_with(prefix)) return false;
    const auto value = root.substr(prefix.size());
    const auto separator = value.find('_');
    if (separator == std::string_view::npos ||
        value.find('_', separator + 1) != std::string_view::npos) {
        return false;
    }
    return IsDecimalToken(value.substr(0, separator)) &&
           IsDecimalToken(value.substr(separator + 1));
}

constexpr bool IsIncrementalFdSource(std::string_view source) {
    constexpr auto self_prefix = "/proc/self/fd/"sv;
    if (source.starts_with(self_prefix)) {
        return IsDecimalToken(source.substr(self_prefix.size()));
    }

    constexpr auto proc_prefix = "/proc/"sv;
    if (!source.starts_with(proc_prefix)) return false;
    const auto remainder = source.substr(proc_prefix.size());
    const auto separator = remainder.find("/fd/"sv);
    return separator != std::string_view::npos &&
           IsDecimalToken(remainder.substr(0, separator)) &&
           IsDecimalToken(remainder.substr(separator + 4));
}

constexpr std::string_view IncrementalMountKey(std::string_view target) {
    constexpr auto prefix = "/data/incremental/"sv;
    constexpr auto suffix = "/mount"sv;
    if (!target.starts_with(prefix) || !target.ends_with(suffix) ||
        target.size() <= prefix.size() + suffix.size()) {
        return {};
    }
    const auto key = target.substr(
            prefix.size(), target.size() - prefix.size() - suffix.size());
    if (!key.starts_with("MT_data_app_"sv) || key.find('/') != std::string_view::npos) return {};
    return key;
}

constexpr bool IsLegacyIncrementalBackingSource(
        std::string_view source,
        std::string_view mount_key) {
    constexpr auto prefix = "/data/incremental/"sv;
    constexpr auto suffix = "/backing_store"sv;
    return !mount_key.empty() && source.starts_with(prefix) && source.ends_with(suffix) &&
           source.substr(prefix.size(), source.size() - prefix.size() - suffix.size()) ==
                   mount_key;
}

static_assert(IsIncrementalFdSource("/proc/self/fd/42"sv));
static_assert(IsIncrementalFdSource("/proc/123/fd/42"sv));
static_assert(!IsIncrementalFdSource("/proc/self/fd/not-a-number"sv));
static_assert(IsIncrementalStorageRoot("/st_234_0"sv));
static_assert(!IsIncrementalStorageRoot("/st_bad_0"sv));
static_assert(IncrementalMountKey(
        "/data/incremental/MT_data_app_vmdl154/mount"sv) == "MT_data_app_vmdl154"sv);
static_assert(IsLegacyIncrementalBackingSource(
        "/data/incremental/MT_data_app_vmdl154/backing_store"sv,
        "MT_data_app_vmdl154"sv));

bool IsTrustedIncrementalPeerGroup(
        const std::vector<const proc_util::MountInfo*>& mounts) {
    if (mounts.size() < 2) return false;

    const auto expected_device = mounts.front()->device;
    const auto expected_source = std::string_view(mounts.front()->source);
    std::string_view mount_key;
    unsigned root_mounts = 0;
    unsigned app_binds = 0;
    for (const auto* mount : mounts) {
        if (mount->type != "incremental-fs" || major(mount->device) != 0 ||
            mount->device != expected_device || mount->source != expected_source ||
            !HasMountOption(mount->vfs_option, "rw") ||
            !HasMountOption(mount->vfs_option, "nosuid") ||
            !HasMountOption(mount->vfs_option, "nodev") ||
            !HasMountOption(mount->vfs_option, "noatime")) {
            return false;
        }

        const auto key = IncrementalMountKey(mount->target);
        if (!key.empty()) {
            if (mount->root != "/" || ++root_mounts > 1) return false;
            mount_key = key;
            continue;
        }
        if (IsDirectChildOf(mount->target, "/data/app/"sv) &&
            IsIncrementalStorageRoot(mount->root)) {
            ++app_binds;
            continue;
        }
        return false;
    }
    if (root_mounts != 1 || app_binds == 0) return false;

    if (!IsIncrementalFdSource(expected_source) &&
        !IsLegacyIncrementalBackingSource(expected_source, mount_key)) {
        return false;
    }

    for (const auto* mount : mounts) {
        const auto sysfs_name = MountOptionValue(mount->fs_option, "sysfs_name="sv);
        // Android 11 / IncFS v1 did not expose sysfs_name. On v2, if the
        // option exists, require the AOSP mount-key prefix so an arbitrary
        // incremental-fs mount cannot claim the compatibility path.
        if (!sysfs_name.empty() && !sysfs_name.starts_with(mount_key)) return false;
    }
    return true;
}

std::unordered_set<unsigned> FindTrustedIncrementalPropagationGroups(
        const std::vector<proc_util::MountInfo>& mountlist) {
    std::unordered_map<unsigned, std::vector<const proc_util::MountInfo*>> grouped_mounts;
    for (const auto& mount : mountlist) {
        const auto group = IncrementalPropagationGroup(mount);
        if (group != 0) grouped_mounts[group].push_back(&mount);
    }

    std::unordered_set<unsigned> trusted_groups;
    for (const auto& [master, mounts] : grouped_mounts) {
        if (IsTrustedIncrementalPeerGroup(mounts)) trusted_groups.emplace(master);
    }
    return trusted_groups;
}

void FindMountInfoLoophole() {
    struct MinorCmp {
        bool operator()(const proc_util::MountInfo& lhs, const proc_util::MountInfo& rhs) const {
            return minor(lhs.device) < minor(rhs.device);
        }
    };
    std::set<proc_util::MountInfo, MinorCmp> unnamed_mountlist;
    auto full_mountlist = proc_util::MountInfo::Scan("self");
    const auto trusted_incfs_groups =
            FindTrustedIncrementalPropagationGroups(full_mountlist);
    std::vector<bool> peer_groups;
    auto mnt_id_data_data = 0;
    auto no_storage = 1;
    auto has_sdcardfs = 0;
    auto reuse_umounted = 1;
    auto sdk = GetAndroidApiLevel();
    for (const auto& mount : full_mountlist) {
        if (mount.target == "/data/data") mnt_id_data_data = mount.id;
        const auto propagation_group = IncrementalPropagationGroup(mount);
        if (trusted_incfs_groups.contains(propagation_group)) {
            LOGI("Accept verified system Incremental FS propagation group {}: {}",
                 propagation_group, mount.target);
            if (mount.optional.master != 0) {
                if (peer_groups.size() < mount.optional.master) {
                    peer_groups.resize(mount.optional.master, false);
                }
                peer_groups[mount.optional.master - 1] = true;
            }
            continue;
        }
        if (mount.optional.master == 0) continue;
        LOGD("master group id {} {}", mount.optional.master, mount.target);
        // https://cs.android.com/android/platform/superproject/+/android14-qpr3-release:frameworks/base/core/jni/com_android_internal_os_Zygote.cpp;l=2371
        if (mount.target == "/storage") no_storage = 0;
        // https://cs.android.com/android/platform/superproject/+/android14-qpr3-release:system/vold/model/EmulatedVolume.cpp;l=165
        if (sdk >= 30 && mount.type == "sdcardfs") has_sdcardfs = 1;
        // Some xiaomi device will umount /mnt/reuse after boot
        if (access("/mnt/reuse", F_OK) != 0 || mount.target == "/mnt/reuse") reuse_umounted = 0;
        if (peer_groups.size() < mount.optional.master) {
            peer_groups.resize(mount.optional.master, false);
        }
        peer_groups[mount.optional.master - 1] = true;
        if (major(mount.device) == 0 && mount.root == "/") {
            unnamed_mountlist.emplace(mount);
        }
    }
    // Keep one transient-unmount allowance only when this namespace contains a
    // structurally verified AOSP Incremental FS mount. Kernel capability alone
    // is not evidence that a missing group came from IncFS and must not weaken
    // this signal on every modern device.
    unsigned allow_count = no_storage + has_sdcardfs + reuse_umounted +
                           static_cast<unsigned>(!trusted_incfs_groups.empty());
    unsigned cnt = 0;
    unsigned index = 0;
    for (const auto& peer_group : peer_groups) {
        ++index;
        if (!peer_group) {
            LOGD("Missing peer group {}", index);
            ++cnt;
        }
        if (cnt > allow_count) {
            LOGE("FindPeerGroupLoophole {} {}", cnt, allow_count);
            MarkAbnormalEnvironment();
        }
    }

    unsigned last_minor = 0;
    for (auto& mount : unnamed_mountlist) {
        if (mount.target == "/dev") {
            last_minor = minor(mount.device);
            continue;
        }
        if (last_minor != 0 && ++last_minor != minor(mount.device)) {
            LOGE("FindMinorDevLoophole, {} {} {}", mount.device, mount.source, mount.target);
            MarkAbnormalEnvironment();
            break;
        }
        if (mount.target == "/sys") {
            break;
        }
    }

    if (sdk < 30) return;
    std::string_view last_source{mnt_strings};
    std::string_view last_mount{last_source.data() + last_source.size() + 1};
    auto mnt_check = FindMountidLoophole(full_mountlist, last_mount);
    auto app_zygote_mount_check = static_cast<uint32_t>(mnt_check_appzygote);
    if (app_zygote_mount_check & APP_ZYGOTE_RESULT_UNAVAILABLE) {
        app_zygote_mount_check = static_cast<uint32_t>(mnt_check);
    }
    auto confirmed_mount_gaps = app_zygote_mount_check & static_cast<uint32_t>(mnt_check);
    if (confirmed_mount_gaps & APP_ZYGOTE_MOUNT_ART_GAP) MarkAbnormalEnvironment();
    if (confirmed_mount_gaps & APP_ZYGOTE_MOUNT_BOOT_GAP) MarkAbnormalEnvironment();
    if (confirmed_mount_gaps & APP_ZYGOTE_MOUNT_DATA_GAP) MarkAbnormalEnvironment();

    if (!SupportStatx()) return;
    struct statx stx{};
    if (syscall(SYS_statx, AT_FDCWD, "/data/data", AT_NO_AUTOMOUNT, STATX_BASIC_STATS | STATX_MNT_ID, &stx) == -1) {
        PLOGE("statx failed");
        return;
    }
    if (stx.stx_mask & STATX_MNT_ID && mnt_id_data_data != 0 && mnt_id_data_data != stx.stx_mnt_id) {
        LOGE("FindMntidLoophole: fake mnt id, expected id {}, but found {}", mnt_id_data_data, stx.stx_mnt_id);
        MarkAbnormalEnvironment();
    }
}

std::string app_apk_path;
uint32_t RunZygotePreloadProbe(JNIEnv* env) {
    uint32_t check_result = 0;

    {
        constexpr const auto SEC = 1'000'000'000l;
        constexpr static auto kAttr = "/proc/self/attr/current";
        struct timespec start{};
        clock_gettime(CLOCK_REALTIME_COARSE, &start);
        usleep(100);
        struct stat st{};
        if (fstatat(AT_FDCWD, kAttr, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            LOGE("err {} {}", errno, strerror(errno));
        } else {
            auto dt =
                    (st.st_ctim.tv_sec - start.tv_sec) * SEC + (st.st_ctim.tv_nsec - start.tv_nsec);
            LOGI("time delta for attr = {} stat ctime = {} start = {}", dt,
                 st.st_atim.tv_sec * SEC + st.st_atim.tv_nsec,
                 start.tv_sec * SEC + start.tv_nsec);
            if (dt < 0) check_result |= APP_ZYGOTE_ATTR_TIME_ANOMALY;
        }
    }

    {
        const char *paths[] = {"/mnt", "/mnt/obb", "/mnt/asec"};
        for (auto &path: paths) {
            // First check selinux context
            std::string ctx;
            if (GetFileCon(path, ctx) >= 0 && ctx == "u:object_r:tmpfs:s0") {
                // Then check if listable
                struct stat st{};
                if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    DIR *dir = opendir(path);
                    if (dir == nullptr) break;
                    struct dirent *entry;
                    while ((entry = readdir(dir)) != nullptr) {
                        // "." and ".." should not be accessible if normal as well
                        check_result |= APP_ZYGOTE_TMPFS_PERMISSION;
                        LOGE("tmpfs permission loophole detected");
                        break;
                    }
                    closedir(dir);
                }
            }
        }
    }

    // Cross-check mnt id hole with main process
    FindMntStrings();
    std::string_view last_source{mnt_strings};
    std::string_view last_mount{last_source.data() + last_source.size() + 1};
    auto mount_list = proc_util::MountInfo::Scan("self");
    auto mnt_check = FindMountidLoophole(mount_list, last_mount);
    check_result |= static_cast<uint32_t>(mnt_check);

    // Must run in the App Zygote before doPreload() returns. The isolated
    // service inherits this bitmask and sends it back to the main process.
    check_result |= CheckDirtySepolicy(env);

    return check_result;
}
