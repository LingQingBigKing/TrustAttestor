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

constexpr auto kSymbolANetwork = "_ZN7android15ANetworkSession10threadLoopEv";

RINLINE std::string GetPropValue(const char* key) {
    std::array<char, PROP_VALUE_MAX> buf{};
    auto len = __system_property_get(key, buf.data());
    if (len <= 0) return {};
    return {buf.data(), static_cast<size_t>(len)};
}

RINLINE bool PropNotEmpty(const char* key) {
    return !GetPropValue(key).empty();
}

RINLINE bool PropEquals(const char* key, std::string_view expect) {
    return GetPropValue(key) == expect;
}

RINLINE bool PropContainsToken(const char* key, std::initializer_list<std::string_view> tokens) {
    auto value = GetPropValue(key);
    if (value.empty()) return false;

    std::string token;
    for (char ch : value) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            token.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        } else {
            if (!token.empty()) {
                for (auto t : tokens) {
                    if (token == t) return true;
                }
                token.clear();
            }
        }
    }
    if (!token.empty()) {
        for (auto t : tokens) {
            if (token == t) return true;
        }
    }
    return false;
}

static inline bool ErrMeansPathExists(int e) {
    // EEXIST：目标本身已存在。
    // ENOTDIR：用于 path/./ 升级探测时，说明某一级组件不是目录；
    return e == EEXIST || e == ENOTDIR;
}

__attribute__((noinline, used, annotate("nofla")))
bool ProbePathExists(const char* path, bool upgraded = false) {
    struct stat st{};
    errno = 0;

    int err = 0;
    if (mkdirat(AT_FDCWD, path, 0644) == -1) {
        err = errno;
    } else {
        unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    }

    bool exists =
            ErrMeansPathExists(err) ||
            access(path, F_OK) == 0 ||
            // faccessat(AT_FDCWD, path, F_OK, 0) == 0 ||
            stat(path, &st) == 0 ||
            fstatat(AT_FDCWD, path, &st, 0) == 0;

    if (!exists && !upgraded) {
        std::string upgraded_path = std::string(path) + "/./";
        exists = ProbePathExists(upgraded_path.c_str(), true);
    }

    if (exists) {
        if (upgraded) MarkFutileHide(1u << 7);
        return true;
    }

    errno = 0;
    if (symlink(path, path) == -1) {
        exists = ErrMeansPathExists(errno);
    } else {
        unlink(path);
    }

    if (exists && upgraded) MarkFutileHide(1u << 7);
    return exists;
}

RINLINE bool FileExists(const char* path) {
    return ProbePathExists(path, false);
}

/*
RINLINE std::string ExecRead(const char* cmd) {
    std::string out;
    FILE* fp = popen(cmd, "r");
    if (!fp) return out;

    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
        if (out.size() > 1024) break;
    }
    pclose(fp);
    return out;
}
 */

RINLINE std::string ToLowerCopy(std::string s) {
    for (auto &ch : s) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return s;
}

RINLINE bool PropEqualsIgnoreCase(const char* key, std::string_view expect) {
    auto value = ToLowerCopy(GetPropValue(key));
    std::string target(expect);
    for (auto &ch : target) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value == target;
}

RINLINE bool PropInIgnoreCase(const char* key, std::initializer_list<std::string_view> candidates) {
    auto value = ToLowerCopy(GetPropValue(key));
    for (auto item : candidates) {
        std::string target(item);
        for (auto &ch : target) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (value == target) return true;
    }
    return false;
}

RINLINE bool IsUnlockedToken(std::string value) {
    value = ToLowerCopy(std::move(value));
    return value == "unlocked" || value == "0" || value == "false" || value == "no";
}

RINLINE bool IsAbnormalBootloaderProp() {
    if (PropInIgnoreCase("ro.boot.verifiedbootstate", {"red", "orange", "yellow"})) return true;
    if (IsUnlockedToken(GetPropValue("ro.secureboot.lockstate"))) return true;
    if (IsUnlockedToken(GetPropValue("ro.boot.vbmeta.device_state"))) return true;
    if (IsUnlockedToken(GetPropValue("ro.boot.flash.locked"))) return true;
    if (IsUnlockedToken(GetPropValue("vendor.boot.vbmeta.device_state"))) return true;
    if (PropInIgnoreCase("vendor.boot.verifiedbootstate", {"red", "orange", "yellow"})) return true;
    if (PropInIgnoreCase("ro.boot.realmebootstate", {"red", "orange", "yellow"})) return true;
    if (IsUnlockedToken(GetPropValue("ro.boot.realme.lockstate"))) return true;
    if (GetPropValue("ro.is_ever_orange") == "0") return true;
    if (PropEqualsIgnoreCase("ro.boot.veritymode", "permissiving") ||
        PropEqualsIgnoreCase("ro.boot.veritymode", "permissive")) return true;
    return false;
}

static std::string JStringToString(JNIEnv* env, jstring js) {
    if (env == nullptr || js == nullptr) {
        return "";
    }
    const char* chars = env->GetStringUTFChars(js, nullptr);
    if (chars == nullptr) {
        return "";
    }
    std::string result(chars);
    env->ReleaseStringUTFChars(js, chars);
    return result;
}

static std::string ReadProcKernelRelease() {
    int fd;
    do {
        fd = open("/proc/sys/kernel/osrelease", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return {};

    std::array<char, 256> buffer{};
    ssize_t length;
    do {
        length = read(fd, buffer.data(), buffer.size() - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0) return {};

    size_t end = static_cast<size_t>(length);
    while (end > 0) {
        const char ch = buffer[end - 1];
        if (ch != '\0' && ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t') break;
        --end;
    }
    return end == 0 ? std::string{} : std::string(buffer.data(), end);
}

static KernelIdentity CollectUnameKernelIdentity() {
    struct utsname uts{};
    if (uname(&uts) != 0) return {};
    KernelIdentity identity;
    identity.release = uts.release;
    identity.buildVersion = uts.version;
    identity.machine = uts.machine;
    identity.available = true;
    return identity;
}

KernelIdentity CollectKernelIdentity() {
    KernelIdentity identity = CollectUnameKernelIdentity();
    const std::string procRelease = ReadProcKernelRelease();
    if (!procRelease.empty()) {
        // procfs is backed directly by the running kernel. Prefer it over the
        // libc uname wrapper whenever the node is readable.
        identity.release = procRelease;
        identity.available = true;
    }
    return identity;
}

bool CheckSpoofKernel(JNIEnv* env) {
    if (env == nullptr) return false;
    const auto unameKernel = CollectUnameKernelIdentity();
    const std::string procKernel = ReadProcKernelRelease();
    const std::string trustedKernel = !procKernel.empty()
            ? procKernel
            : (unameKernel.available ? unameKernel.release : std::string{});
    if (trustedKernel.empty()) return false;

    std::string true_kernel;
    jclass systemClass = env->FindClass("java/lang/System");
    if (systemClass != nullptr) {
        jmethodID getProperty = env->GetStaticMethodID(
                systemClass,
                "getProperty",
                "(Ljava/lang/String;)Ljava/lang/String;");
        if (getProperty != nullptr) {
            jstring key = env->NewStringUTF("os.version");
            jstring value = (jstring)env->CallStaticObjectMethod(systemClass, getProperty, key);
            if (!env->ExceptionCheck()) {
                true_kernel = JStringToString(env, value);
            } else {
                env->ExceptionClear();
            }
            if (value) env->DeleteLocalRef(value);
            if (key) env->DeleteLocalRef(key);
        }
        env->DeleteLocalRef(systemClass);
    }

    if (!procKernel.empty() && unameKernel.available && unameKernel.release != procKernel) {
        return true;
    }

    if (!true_kernel.empty() && true_kernel != trustedKernel) {
        return true;
    }

    return false;
}

static bool CheckZygiskByFork() {
    pid_t child_pid = fork();
    if (child_pid < 0) {
        LOGE("fork failed: {}", strerror(errno));
        return false;
    }

    if (child_pid == 0) {
        // 子进程：什么都不做，保持存活，等待父进程 attach
        // 用 pause() 最简单；被 PTRACE_ATTACH 后会先收到停止信号
        for (;;) {
            pause();
        }
        _exit(0);
    }

    // 父进程
    if (ptrace(PTRACE_ATTACH, child_pid, nullptr, nullptr) < 0) {
        LOGE("ptrace attach failed: {}", strerror(errno));
        KillAndReap(child_pid);
        return false;
    }

    // 等待子进程真正进入 ptrace-stop
    int status = 0;
    if (!WaitPidWithTimeout(child_pid, &status, 500)) {
        LOGE("waitpid after attach failed: {}", strerror(errno));
        ptrace(PTRACE_DETACH, child_pid, nullptr, nullptr);
        KillAndReap(child_pid);
        return false;
    }

    unsigned long msg = 0;
    if (ptrace(PTRACE_GETEVENTMSG, child_pid, nullptr, &msg) < 0) {
        LOGE("ptrace geteventmsg failed: {}", strerror(errno));
        ptrace(PTRACE_DETACH, child_pid, nullptr, nullptr);
        KillAndReap(child_pid);
        return false;
    }

    bool detected = static_cast<pid_t>(msg) == ppid;
    ptrace(PTRACE_DETACH, child_pid, nullptr, nullptr);
    KillAndReap(child_pid);
    return detected;
}

void ConventionalTests(JNIEnv *env) {
    if (IsAbnormalBootloaderProp()) {
        LOGE("Bootloader unlocked");
        MarkConventional(1u << 0);
    }

    FILE* fp = fopen("/proc/self/mountinfo", "r");
    char line[PATH_MAX];

    std::string_view last_source{mnt_strings};
    std::string_view last_mount{last_source.data() + last_source.size() + 1};
    std::string_view last_fs{last_mount.data() + last_mount.size() + 1};

    LOGD("last source={} mount={} fs={}", last_source, last_mount, last_fs);

    bool need_check = false;

    if (last_source == "KSU" ||
        last_source == "magisk" ||
        last_source == "APatch" ||
        last_mount.starts_with("/data/adb")) {
        MarkFutileHide(1u << 3);
        LOGE("found suspicious source name in mntstrings remain!!!");
    } else {
        need_check = last_mount.starts_with("/system/")
                     || last_mount.starts_with("/vendor/")
                     || last_mount.starts_with("/product/")
                     || last_mount.starts_with("/system_ext/");
    }

    LOGD("need check: {}", need_check);

    bool senstive_mount_exists = false;
    bool debug_ramdisk_exists = false;

    int mount_max_ext4 = 0;
    std::unordered_map<std::string, bool> mount_ext4;

    while (fp != nullptr && fgets(line, PATH_MAX, fp)) {
        std::string_view line_sv(line);
        if (line_sv.find("/adb/modules") != std::string_view::npos ||
            (line_sv.find("/debug_ramdisk") != std::string_view::npos &&
             (line_sv.find("magisk") != std::string_view::npos ||
              line_sv.find("KSU") != std::string_view::npos ||
              line_sv.find("APatch") != std::string_view::npos)) ||
            line_sv.find("zygisk") != std::string_view::npos) {
            LOGE("Found /adb/modules in mountinfo");
            MarkConventional(1u << 1);
        }
        // TODO: parse mountinfo
        if (need_check) {
            senstive_mount_exists |= line_sv.find(last_source) != std::string_view::npos
                                     && line_sv.find(last_mount) != std::string_view::npos
                                     && line_sv.find(last_fs) != std::string_view::npos;
        }
        debug_ramdisk_exists |= line_sv.find("/debug_ramdisk") != std::string_view::npos;

        if (line_sv.find(" ext4 ") != std::string_view::npos && line_sv.find("/loop") != std::string_view::npos) {
            std::string line_str(line);
            size_t pos = line_str.find("/loop");
            if (pos != std::string::npos) {
                std::string num_str;
                for (size_t i = pos+5; i < line_str.size() && isdigit(line_str[i]); i++) {
                    num_str += line_str[i];
                }
                if (!num_str.empty()) {
                    int n = atoi(num_str.c_str());
                    if (n > mount_max_ext4) mount_max_ext4 = n;
                }
            }
        }

    }
    if (fp != nullptr && need_check && !senstive_mount_exists) {
        MarkFutileHide(1u << 3);
        LOGE("found suspicious bind mount in mntstrings remain!!!");
    }

    struct stat st1{}, st2{};
    // Check whether device id of /debug_ramdisk is same with root
    if (!debug_ramdisk_exists && stat("/debug_ramdisk", &st1) == 0 &&
        stat("/", &st2) == 0 && (st1.st_dev != st2.st_dev)) {
        MarkFutileHide(1u << 4);
        LOGE("debug_ramdisk mountpoint detected");
    }

    DIR* dir = opendir("/proc/fs/ext4");
    if(dir){
        for(int i=0;i<=mount_max_ext4;i++){
            mount_ext4["loop" + std::to_string(i)] = true;
        }
        struct dirent* ent;
        while((ent=readdir(dir))!=nullptr){
            std::string name = ent->d_name;
            if(name.find("loop")!=std::string::npos && !mount_ext4.count(name)){
                // 检测到 KernelSU / APatch 隐藏ext4镜像
                LOGE("Detect KernelSU/APatch ext4 loop image");
                MarkFutileHide(1u << 10);
                break;
            }
        }
        closedir(dir);
    }

    if (fp != nullptr) fclose(fp);

    const char* paths[] = {"/metadata/magisk", "/sbin/su", "/system/bin/su", "/system/xbin/su"};
    for (auto& path: paths) {
        if (FileExists(path)) {
            LOGE("Found su in {}", path);
            MarkConventional(1u << 2);
        }
    }

    struct stat st{};
    char devpts[16];
    for (int i = 0; i <= 5; i++) {
        sprintf(devpts, "/dev/pts/%d", i);
        if (stat(devpts, &st) == 0 && st.st_uid == 0) {
            LOGE("Found root shell {}", devpts);
            MarkConventional(1u << 2);
        }
    }

    bool adb_trace = false;
    adb_trace |= PropContainsToken("persist.sys.usb.config", {"adb", "hdb"});
    adb_trace |= PropContainsToken("sys.usb.config", {"adb", "hdb"});
    adb_trace |= PropContainsToken("sys.usb.state", {"adb", "hdb"});
    adb_trace |= PropNotEmpty("persist.security.adbinput");
    adb_trace |= PropNotEmpty("persist.security.adbinstall");
    adb_trace |= PropEquals("init.svc.adbd", "running");
    adb_trace |= PropNotEmpty("service.adb.root");
    if (adb_trace) {
        LOGE("Found ADB debugging traces");
        MarkConventional(1u << 5);
    }

    auto boot_avb_version = GetPropValue("ro.boot.avb_version");
    if (!boot_avb_version.empty()) {
        auto vbmeta_avb_version = GetPropValue("ro.boot.vbmeta.avb_version");
        auto vbmeta_device_state = GetPropValue("ro.boot.vbmeta.device_state");
        auto vbmeta_hash_alg = GetPropValue("ro.boot.vbmeta.hash_alg");
        auto vbmeta_size = GetPropValue("ro.boot.vbmeta.size");
        if (vbmeta_avb_version.empty() ||
            vbmeta_device_state.empty() ||
            vbmeta_hash_alg.empty() ||
            vbmeta_size.empty()) {
            LOGE("Found incomplete vbmeta properties while avb is present");
            MarkConventional(1u << 6);
        }
    }

    auto crypto_state = GetPropValue("ro.crypto.state");
    if (!crypto_state.empty() && crypto_state != "encrypted") {
        LOGE("Data partition is not encrypted, ro.crypto.state={}", crypto_state);
        MarkConventional(1u << 7);
    }


    bool busybox_found = false;
    const char* busybox_paths[] = {
            "/sbin/busybox",
            "/system/bin/busybox",
            "/system/xbin/busybox",
            "/vendor/bin/busybox",
            "/odm/bin/busybox",
            "/product/bin/busybox"
    };
    for (auto& path : busybox_paths) {
        if (FileExists(path)) {
            busybox_found = true;
            break;
        }
    }
    if (busybox_found) {
        LOGE("Found BusyBox traces");
        MarkConventional(1u << 8);
    }

    if (FileExists("/data/local/tmp/shizuku") ||
        FileExists("/data/local/tmp/shizuku_starter")) {
        LOGE("Found Shizuku traces");
        MarkConventional(1u << 9);
    }

    if (FileExists("/storage/emulated/elgg") ||
        FileExists("/storage/emulated/legacy")) {
        LOGE("Found GameGuardian traces");
        MarkConventional(1u << 10);
    }

    bool kernelsu_trace = false;
    for (const auto& mount : proc_util::MountInfo::Scan("self")) {
        const bool official_ksu_source = mount.source == "KSU";
        if (!official_ksu_source) continue;
        kernelsu_trace = true;
        LOGE("Found KernelSU mount: type={} source={} target={}",
             mount.type, mount.source, mount.target);
    }

    const char* kernelsu_paths[] = {
            "/dev/susfs4ksu",
            "/sys/module/kernelsu",
            "/proc/ksu_uid_scanner",
            "/data/local/tmp/ksud",
            "/data/local/tmp/ksu-helper",
            "/data/local/tmp/ksu-payload",
            "/data/local/tmp/temp_su.sock",
    };
    for (const char* path : kernelsu_paths) {
        if (!FileExists(path)) continue;
        kernelsu_trace = true;
        LOGE("Found KernelSU trace: {}", path);
    }
    if (kernelsu_trace) {
        MarkConventional(1u << 11);
    }

    /*
    auto service_out = ExecRead("service 2>/dev/null");
    if (!service_out.empty()) {
        std::string prefix;
        for (char ch : service_out) {
            if (ch == '\r' || ch == '\n') break;
            prefix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
            if (prefix.size() >= 5) break;
        }
        if (prefix != "usage") {
            LOGE("Found forged service command output: {}", prefix);
            MarkConventional(1u << 12);
        }
    }
    */

    if (PropNotEmpty("persist.hyperceiler.log.level") ||
        PropNotEmpty("persist.sys.vold_app_data_isolation_enabled") ||
        PropNotEmpty("persist.zygote.app_data_isolation")) {
        LOGE("Found suspicious persistent properties");
        MarkConventional(1u << 12);
    }

    const char* sepolicy_paths[] = {"/vendor/etc/selinux/vendor_sepolicy.cil",
                                    "/system_ext/etc/selinux/system_ext_sepolicy.cil",
                                    "/vendor/etc/selinux/vendor_file_contexts"};
    for (auto &path: sepolicy_paths) {
        FILE* sepolicy = fopen(path, "r");
        if (sepolicy == nullptr) break;
        char rule[PATH_MAX];
        while (fgets(rule, PATH_MAX, sepolicy)) {
            std::string_view rule_sv(rule);
            if (rule_sv.find("hal_lineage") != std::string_view::npos ||
                rule_sv.find("hal_aospa") != std::string_view::npos ||
                rule_sv.find(".lineage") != std::string_view::npos ||
                rule_sv.find(".aospa") != std::string_view::npos) {
                LOGE("Found third party service context");
                MarkConventional(1u << 4);
                break;
            }
        }
        fclose(sepolicy);
    }

    if (CheckSpoofKernel(env)) {
        MarkFutileHide(1u << 8);
        LOGE("spoof kernel detected");
    }

    if (CheckZygiskByFork()) {
        MarkFutileHide(1u << 9);
        LOGE("zygisk detected");
    }

    do {
        if (GetAndroidApiLevel() < 29) break;
        auto symbol = kSymbolANetwork;
        auto getThreadLoop = sSymbolList[std::string(symbol)];
        if (!getThreadLoop) break;
        LOGE("Found third party rom symbol");
        MarkConventional(1u << 4);
    } while (false);
}
