#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <ranges>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "checker_internal.h"
#include "logging.h"

namespace readproc_probe {

struct NamespaceKey {
    uint64_t device = 0;
    uint64_t inode = 0;

    bool operator==(const NamespaceKey& other) const {
        return device == other.device && inode == other.inode;
    }
};

struct NamespaceKeyHash {
    size_t operator()(const NamespaceKey& key) const {
        auto mixed = key.device ^ (key.inode + 0x9E3779B97F4A7C15ULL +
                                   (key.device << 6) + (key.device >> 2));
        return std::hash<uint64_t>{}(mixed);
    }
};

struct MountView {
    pid_t pid = -1;
    NamespaceKey namespace_key;
    uint64_t content_hash = 0;
};

struct TopologyView {
    pid_t pid = -1;
    uint64_t content_hash = 0;
};

static bool ReadBoundedFile(const std::string& path, std::string& output, size_t limit) {
    output.clear();
    int fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd == -1) return false;

    std::array<char, 16 * 1024> buffer{};
    bool ok = true;
    for (;;) {
        auto count = TEMP_FAILURE_RETRY(read(fd, buffer.data(), buffer.size()));
        if (count < 0) {
            ok = false;
            break;
        }
        if (count == 0) break;
        if (output.size() + static_cast<size_t>(count) > limit) {
            ok = false;
            break;
        }
        output.append(buffer.data(), static_cast<size_t>(count));
    }
    close(fd);
    return ok && !output.empty();
}

static bool ProbeReadable(const std::string& path) {
    int fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd == -1) return false;
    char byte = 0;
    auto count = TEMP_FAILURE_RETRY(read(fd, &byte, sizeof(byte)));
    close(fd);
    return count > 0;
}

static bool HasReadProcGroup() {
    auto count = getgroups(0, nullptr);
    if (count <= 0) return false;
    std::vector<gid_t> groups(static_cast<size_t>(count));
    count = getgroups(count, groups.data());
    if (count <= 0) return false;
    return std::find(groups.begin(), groups.begin() + count, static_cast<gid_t>(3009)) !=
           groups.begin() + count;
}

static uint64_t HashBytes(std::string_view value) {
    uint64_t hash = 1469598103934665603ULL;
    for (unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool NormalizeMountInfo(
        std::string_view mountinfo,
        uint64_t& content_hash,
        uint8_t& propagation_mode) {
    std::vector<std::string> records;
    propagation_mode = 0;
    size_t line_start = 0;
    bool first_record = true;

    while (line_start < mountinfo.size()) {
        auto line_end = mountinfo.find('\n', line_start);
        if (line_end == std::string_view::npos) line_end = mountinfo.size();
        auto line = mountinfo.substr(line_start, line_end - line_start);
        line_start = line_end + 1;
        if (line.empty()) continue;

        std::array<std::string_view, 6> fields{};
        size_t cursor = 0;
        bool valid = true;
        for (auto& field : fields) {
            auto next = line.find(' ', cursor);
            if (next == std::string_view::npos) {
                valid = false;
                break;
            }
            field = line.substr(cursor, next - cursor);
            cursor = next + 1;
        }
        if (!valid) continue;

        auto separator = line.find(" - ", cursor);
        if (separator == std::string_view::npos) continue;
        auto optional = line.substr(cursor, separator - cursor);
        cursor = separator + 3;

        auto type_end = line.find(' ', cursor);
        if (type_end == std::string_view::npos) continue;
        auto fs_type = line.substr(cursor, type_end - cursor);
        cursor = type_end + 1;

        auto source_end = line.find(' ', cursor);
        if (source_end == std::string_view::npos) continue;
        auto source = line.substr(cursor, source_end - cursor);
        auto super_options = line.substr(source_end + 1);

        if (first_record) {
            if (optional.starts_with("shared:")) propagation_mode = 1u;
            else if (optional.starts_with("master:")) propagation_mode = 2u;
            first_record = false;
        }

        // Match Privisolated's comparison surface: mount IDs, parent IDs,
        // device numbers, and propagation peer IDs are namespace-local noise.
        std::string record;
        record.reserve(source.size() + fields[3].size() + fields[4].size() +
                       fs_type.size() + fields[5].size() + super_options.size() + 6);
        record.append(source).push_back(' ');
        record.append(fields[3]).push_back(' ');  // root
        record.append(fields[4]).push_back(' ');  // mount point
        record.append(fs_type).push_back(' ');
        record.append(fields[5]).push_back(' ');  // mount options
        record.append(super_options);
        records.emplace_back(std::move(record));
    }

    if (records.empty()) return false;
    std::ranges::sort(records);
    uint64_t hash = 1469598103934665603ULL;
    for (const auto& record : records) {
        for (unsigned char byte : record) {
            hash ^= byte;
            hash *= 1099511628211ULL;
        }
        hash ^= static_cast<unsigned char>('\n');
        hash *= 1099511628211ULL;
    }
    content_hash = hash;
    return true;
}

static bool ContainsMountTrace(std::string_view mountinfo) {
    std::string lower(mountinfo);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    constexpr std::array<std::string_view, 8> kMarkers = {
            "/data/adb/",
            "/adb/modules",
            "/debug_ramdisk/",
            ".magisk/",
            "magisk",
            "kernelsu",
            "zygisk",
            "apatch",
    };
    return std::ranges::any_of(kMarkers, [&](std::string_view marker) {
        return lower.find(marker) != std::string::npos;
    });
}

static std::string ProcPath(pid_t pid, std::string_view leaf) {
    return "/proc/" + std::to_string(pid) + "/" + std::string(leaf);
}

static std::string LowerAscii(std::string_view value) {
    std::string lower(value);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower;
}

static std::string_view FirstArgument(std::string_view cmdline) {
    auto end = cmdline.find('\0');
    return cmdline.substr(0, end == std::string_view::npos ? cmdline.size() : end);
}

static std::string_view BaseName(std::string_view path) {
    auto slash = path.find_last_of('/');
    return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

static bool ReadMountNamespace(pid_t pid, NamespaceKey& key) {
    struct stat namespace_stat{};
    if (stat(ProcPath(pid, "ns/mnt").c_str(), &namespace_stat) != 0) return false;
    key.device = static_cast<uint64_t>(namespace_stat.st_dev);
    key.inode = static_cast<uint64_t>(namespace_stat.st_ino);
    return true;
}

static bool ConfirmNamespaceMismatch(const MountView& first, const MountView& second) {
    usleep(20'000);

    NamespaceKey first_key;
    NamespaceKey second_key;
    if (!ReadMountNamespace(first.pid, first_key) ||
        !ReadMountNamespace(second.pid, second_key) || first_key != second_key) {
        return false;
    }

    std::string first_mountinfo;
    std::string second_mountinfo;
    if (!ReadBoundedFile(ProcPath(first.pid, "mountinfo"), first_mountinfo, 4 * 1024 * 1024) ||
        !ReadBoundedFile(ProcPath(second.pid, "mountinfo"), second_mountinfo, 4 * 1024 * 1024)) {
        return false;
    }
    return HashBytes(first_mountinfo) != HashBytes(second_mountinfo);
}

static int PropagationModeCount(uint8_t modes) {
    return ((modes & 1u) != 0 ? 1 : 0) + ((modes & 2u) != 0 ? 1 : 0);
}

static bool ConfirmTopologyMismatch(
        const std::unordered_map<uint64_t, TopologyView>& views,
        uint8_t propagation_modes) {
    auto expected = PropagationModeCount(propagation_modes);
    if (expected == 0 || views.size() <= static_cast<size_t>(expected)) return false;

    usleep(20'000);
    std::unordered_set<uint64_t> confirmed_views;
    uint8_t confirmed_modes = 0;
    for (const auto& [_, view] : views) {
        std::string mountinfo;
        if (!ReadBoundedFile(ProcPath(view.pid, "mountinfo"), mountinfo, 4 * 1024 * 1024)) {
            continue;
        }
        uint64_t normalized_hash = 0;
        uint8_t mode = 0;
        if (!NormalizeMountInfo(mountinfo, normalized_hash, mode) ||
            normalized_hash != view.content_hash) {
            continue;
        }
        confirmed_views.insert(normalized_hash);
        confirmed_modes |= mode;
    }

    expected = PropagationModeCount(confirmed_modes);
    return expected > 0 && confirmed_views.size() > static_cast<size_t>(expected);
}

static uint32_t DetectProcessFromCmdline(std::string_view cmdline) {
    auto lower = LowerAscii(BaseName(FirstArgument(cmdline)));
    if (lower == "zn-daemon") return READPROC_ZN_DAEMON;
    if (lower == "lspd") return READPROC_LSPD;
    if (lower == "trickystore") return READPROC_TRICKY_STORE;
    if (lower == "teesimulator" ||
        LowerAscii(cmdline).find("org.matrix.teesimulator.app") != std::string::npos) {
        return READPROC_TEESIM_RS_DAEMON;
    }
    return 0;
}

static bool IsTeeSimulatorHookTarget(std::string_view cmdline) {
    auto executable = LowerAscii(BaseName(FirstArgument(cmdline)));
    return executable == "keystore2" || executable == "com.tencent.soter.soterserver";
}

static bool ContainsMappedLibrary(std::string_view maps, std::string_view library) {
    size_t line_start = 0;
    while (line_start < maps.size()) {
        auto line_end = maps.find('\n', line_start);
        if (line_end == std::string_view::npos) line_end = maps.size();
        auto line = maps.substr(line_start, line_end - line_start);
        line_start = line_end + 1;

        auto path_start = line.find('/');
        if (path_start == std::string_view::npos) continue;
        auto path = line.substr(path_start);
        if (auto deleted = path.find(" (deleted)"); deleted != std::string_view::npos) {
            path = path.substr(0, deleted);
        }
        if (BaseName(path) == library) return true;
    }
    return false;
}

static uint32_t Check() {
    uint32_t flags = 0;
    const bool has_readproc = HasReadProcGroup();
    if (has_readproc) flags |= READPROC_GID_3009;

    const bool mountinfo_readable = ProbeReadable("/proc/1/mountinfo");
    const bool cmdline_readable = ProbeReadable("/proc/1/cmdline");
    const bool status_readable = ProbeReadable("/proc/1/status");
    const bool maps_readable = ProbeReadable("/proc/1/maps");
    if (mountinfo_readable) flags |= READPROC_MOUNTINFO_READABLE;
    if (cmdline_readable) flags |= READPROC_CMDLINE_READABLE;
    if (status_readable) flags |= READPROC_STATUS_READABLE;
    if (maps_readable) flags |= READPROC_MAPS_READABLE;

    LOGI("READPROC capability test: gid3009={} mountinfo={} cmdline={} status={} maps={}",
         has_readproc, mountinfo_readable, cmdline_readable, status_readable, maps_readable);

    if (!has_readproc) {
        flags |= READPROC_RESULT_UNAVAILABLE;
        return flags | READPROC_CHECK_COMPLETED;
    }

    DIR* proc = opendir("/proc");
    if (proc == nullptr) {
        flags |= READPROC_RESULT_UNAVAILABLE;
        return flags | READPROC_CHECK_COMPLETED;
    }

    std::unordered_map<NamespaceKey, MountView, NamespaceKeyHash> first_views;
    std::unordered_map<uint64_t, TopologyView> topology_views;
    std::vector<std::pair<MountView, MountView>> mismatches;
    uint8_t propagation_modes = 0;
    int mountinfo_scanned = 0;
    int foreign_mountinfo_scanned = 0;
    int cmdline_scanned = 0;
    int foreign_cmdline_scanned = 0;
    int maps_scanned = 0;
    int foreign_maps_scanned = 0;
    int traced = 0;
    int named_processes = 0;
    const auto self_pid = getpid();

    while (auto* entry = readdir(proc)) {
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
        char* end = nullptr;
        auto parsed_pid = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || parsed_pid <= 0 || parsed_pid > INT_MAX) {
            continue;
        }

        auto pid = static_cast<pid_t>(parsed_pid);
        std::string cmdline;
        bool teesim_daemon = false;
        bool teesim_hook_target = false;
        if (ReadBoundedFile(ProcPath(pid, "cmdline"), cmdline, 64 * 1024)) {
            ++cmdline_scanned;
            if (pid != self_pid) {
                ++foreign_cmdline_scanned;
                flags |= READPROC_CMDLINE_READABLE;
            }
            auto process_finding = DetectProcessFromCmdline(cmdline);
            if (process_finding != 0) {
                ++named_processes;
                flags |= process_finding;
                const char* name = process_finding == READPROC_ZN_DAEMON ? "zn-daemon" :
                                   process_finding == READPROC_LSPD ? "lspd" :
                                   process_finding == READPROC_TRICKY_STORE ? "TrickyStore" :
                                   "TEESimulator-RS";
                LOGE("READPROC process detected: pid={} name={}", pid, name);
            }
            teesim_daemon = (process_finding & READPROC_TEESIM_RS_DAEMON) != 0;
            teesim_hook_target = IsTeeSimulatorHookTarget(cmdline);
        }

        if (teesim_daemon || teesim_hook_target) {
            std::string maps;
            if (ReadBoundedFile(ProcPath(pid, "maps"), maps, 4 * 1024 * 1024)) {
                ++maps_scanned;
                if (pid != self_pid) {
                    ++foreign_maps_scanned;
                    flags |= READPROC_MAPS_READABLE;
                }
                if (teesim_hook_target && ContainsMappedLibrary(maps, "libTEESimulator.so")) {
                    flags |= READPROC_TEESIM_RS_HOOK;
                    LOGE("READPROC TEESimulator-RS hook mapping detected in pid {}", pid);
                }
                if (teesim_daemon && ContainsMappedLibrary(maps, "libcertgen.so")) {
                    LOGI("READPROC TEESimulator-RS daemon has libcertgen.so mapping in pid {}", pid);
                }
            }
        }

        std::string mountinfo;
        if (!ReadBoundedFile(ProcPath(pid, "mountinfo"), mountinfo, 4 * 1024 * 1024)) continue;
        ++mountinfo_scanned;
        if (pid != self_pid) {
            ++foreign_mountinfo_scanned;
            flags |= READPROC_MOUNTINFO_READABLE;
        }
        if (ContainsMountTrace(mountinfo)) {
            ++traced;
            flags |= READPROC_MOUNT_TRACE;
            LOGE("READPROC mount trace found in pid {}", pid);
        }

        uint64_t normalized_hash = 0;
        uint8_t propagation_mode = 0;
        if (NormalizeMountInfo(mountinfo, normalized_hash, propagation_mode)) {
            propagation_modes |= propagation_mode;
            topology_views.try_emplace(normalized_hash, TopologyView{pid, normalized_hash});
        }

        NamespaceKey namespace_key;
        if (!ReadMountNamespace(pid, namespace_key)) continue;
        MountView view{pid, namespace_key, HashBytes(mountinfo)};
        auto [it, inserted] = first_views.emplace(namespace_key, view);
        if (!inserted && it->second.content_hash != view.content_hash && mismatches.size() < 4) {
            mismatches.emplace_back(it->second, view);
        }
    }
    closedir(proc);

    for (const auto& mismatch : mismatches) {
        if (ConfirmNamespaceMismatch(mismatch.first, mismatch.second)) {
            flags |= READPROC_NAMESPACE_VIEW_MISMATCH;
            LOGE("READPROC mount namespace view mismatch: pid {} vs {}",
                 mismatch.first.pid, mismatch.second.pid);
            break;
        }
    }

    if ((flags & READPROC_NAMESPACE_VIEW_MISMATCH) == 0 &&
        ConfirmTopologyMismatch(topology_views, propagation_modes)) {
        flags |= READPROC_NAMESPACE_VIEW_MISMATCH;
        LOGE("READPROC normalized mount topology mismatch: views={} expected={}",
             topology_views.size(), PropagationModeCount(propagation_modes));
    }

    LOGI("READPROC proc scan: mountinfo={} foreign_mountinfo={} cmdline={} foreign_cmdline={} "
         "maps={} foreign_maps={} namespaces={} views={} expected={} traces={} "
         "named_processes={} flags={:#x}",
         mountinfo_scanned, foreign_mountinfo_scanned, cmdline_scanned,
         foreign_cmdline_scanned, maps_scanned, foreign_maps_scanned,
         first_views.size(), topology_views.size(),
         PropagationModeCount(propagation_modes), traced, named_processes, flags);
    if (foreign_mountinfo_scanned == 0 && foreign_cmdline_scanned == 0) {
        flags |= READPROC_RESULT_UNAVAILABLE;
    }
    return flags | READPROC_CHECK_COMPLETED;
}

} // namespace readproc_probe

uint32_t ReadProcProbeCheck() {
    return readproc_probe::Check();
}

void FindReadProcDetection(JNIEnv* env, jobject context) {
    if (GetAndroidApiLevel() < 29) return;

    auto probe_class = env->FindClass("com/lingqing/trustattestor/ReadProcProbe");
    if (probe_class == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("READPROC probe class unavailable");
        return;
    }
    auto probe_method = env->GetStaticMethodID(
            probe_class, "awaitResult", "(Landroid/content/Context;)I");
    if (probe_method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(probe_class);
        LOGE("READPROC probe method unavailable");
        return;
    }

    auto check = env->CallStaticIntMethod(probe_class, probe_method, context);
    env->DeleteLocalRef(probe_class);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("READPROC probe invocation failed");
        return;
    }

    auto flags = static_cast<uint32_t>(check);
    MarkReadProc(flags & kReadProcFindingMask);
    sReadProc |= flags;
    // The probe runs in a separate isolated PID. Mirror its capability result
    // here so logcat captures filtered to the main application PID still show
    // whether the READPROC service actually started and what it could read.
    LOGD("READPROC capability result: gid3009={} mountinfo={} cmdline={} status={} maps={} flags={:#x}",
         (flags & READPROC_GID_3009) != 0,
         (flags & READPROC_MOUNTINFO_READABLE) != 0,
         (flags & READPROC_CMDLINE_READABLE) != 0,
         (flags & READPROC_STATUS_READABLE) != 0,
         (flags & READPROC_MAPS_READABLE) != 0,
         flags);
    LOGI("READPROC result={:#x} completed={} available={}",
         sReadProc,
         (sReadProc & READPROC_CHECK_COMPLETED) != 0,
         (sReadProc & READPROC_RESULT_UNAVAILABLE) == 0);
}
