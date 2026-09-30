#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <string_view>

#include "checker_internal.h"
#include "logging.h"

namespace {

constexpr unsigned long kGetInfo = _IOR('K', 2, uint32_t[4]);
constexpr unsigned long kGetInfoLegacy = _IOC(_IOC_READ, 'K', 2, 0);
constexpr std::string_view kDriverName = "[ksu_driver]";

struct GetInfoCmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
    uint32_t uapiVersion;
};

struct GetInfoLegacyCmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
};

bool ValidVersion(uint32_t version) {
    // Git-backed builds use 30000 + revision, but KernelSU deliberately falls
    // back to version 16 when its build has no Git metadata.
    return version != 0 && version < 1'000'000;
}

bool ReadInfo(int fd, GetInfoCmd& info) {
    memset(&info, 0, sizeof(info));
    if (ioctl(fd, kGetInfo, &info) == 0 && ValidVersion(info.version)) {
        return true;
    }

    GetInfoLegacyCmd legacy{};
    if (ioctl(fd, kGetInfoLegacy, &legacy) != 0 || !ValidVersion(legacy.version)) {
        return false;
    }
    info.version = legacy.version;
    info.flags = legacy.flags;
    info.features = legacy.features;
    info.uapiVersion = 0;
    return true;
}

bool ParseFdName(const char* name, int& fd) {
    if (name == nullptr || *name == '\0') return false;
    int value = 0;
    for (const char* p = name; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
        if (value > 1'000'000) return false;
        value = value * 10 + (*p - '0');
    }
    fd = value;
    return true;
}

bool ScanInheritedDriverFd() {
    int dirFd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd < 0) {
        MarkKernelSuProbe(kernelsu_probe::FD_SCAN_UNAVAILABLE);
        LOGD("KernelSU fd scan unavailable: {}", strerror(errno));
        return false;
    }

    DIR* dir = fdopendir(dirFd);
    if (dir == nullptr) {
        close(dirFd);
        MarkKernelSuProbe(kernelsu_probe::FD_SCAN_UNAVAILABLE);
        LOGD("KernelSU fd enumeration unavailable: {}", strerror(errno));
        return false;
    }

    bool found = false;
    char linkTarget[256];
    while (dirent* entry = readdir(dir)) {
        int fd = -1;
        if (!ParseFdName(entry->d_name, fd) || fd == dirFd) continue;

        const ssize_t length = readlinkat(dirFd, entry->d_name, linkTarget,
                                          sizeof(linkTarget) - 1);
        if (length <= 0) continue;
        linkTarget[length] = '\0';
        const std::string_view target(linkTarget, static_cast<size_t>(length));
        if (target.find(kDriverName) == std::string_view::npos) continue;

        found = true;
        MarkKernelSuProbe(kernelsu_probe::FD_PRESENT);
        GetInfoCmd info{};
        if (ReadInfo(fd, info)) {
            MarkKernelSuProbe(kernelsu_probe::FD_INFO_VALID);
            sKernelSuVersion = info.version;
            sKernelSuFlags = info.flags;
            sKernelSuUapiVersion = info.uapiVersion;
            LOGI("KernelSU driver fd confirmed: fd={} version={} flags={:#x} uapi={}",
                 fd, info.version, info.flags, info.uapiVersion);
        } else {
            LOGD("Found [ksu_driver] fd {}, but GET_INFO was unavailable", fd);
        }
    }

    closedir(dir);
    return found;
}

}  // namespace

void FindKernelSuProbe() {
    ScanInheritedDriverFd();
    // The active install interface is intentionally not probed: on some kernels
    // even a restricted child can surface a system crash dialog. Absence of that
    // unsafe probe is not an unavailable finding.
}
