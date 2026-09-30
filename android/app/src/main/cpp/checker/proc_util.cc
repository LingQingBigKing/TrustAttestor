#include "proc_util.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <array>
#include <cinttypes>
#include <memory>
#include <fcntl.h>

using sFILE = std::unique_ptr<FILE, void (*)(FILE *)>;

sFILE open_file(const char *path, const char *mode);

sFILE open_file(const char *path, const char *mode) {
    return sFILE(fopen(path, mode), [](auto fp) { fp && fclose(fp); });
}

template<typename T = int, int base = 10>
static T parse_num(std::string_view s) {
    T val = 0;
    for (char c : s) {
        if (isdigit(c)) {
            c -= '0';
        } else if (base > 10 && isalpha(c)) {
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        } else {
            return -1;
        }
        if (c >= base) {
            return -1;
        }
        val *= base;
        val += c;
    }
    return val;
}



namespace proc_util::
inline v2 {
[[maybe_unused]] std::vector<MapInfo> MapInfo::AdoptFd(int fd) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fdopen(fd, "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s",
                       &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(MapInfo{start, end, 0, perm[3] == 'p', off,
                                                  static_cast<dev_t>(makedev(dev_major,
                                                                             dev_minor)),
                                                  inode, line + path_off});
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

std::vector<MapInfo> MapInfo::Scan() {
    int fd = open("/proc/self/maps", O_RDONLY);
    return AdoptFd(fd);
}

[[maybe_unused]] std::vector<MountInfo> MountInfo::Scan(std::string pid) {
    std::vector<MountInfo> info;
    std::string path = "/proc/" + pid + "/mountinfo";
    auto mountinfo = open_file(path.c_str(), "r");
    if (mountinfo) {
        char *buf = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&buf, &len, mountinfo.get())) > 0) {
            auto line = std::string_view(buf, read - 1);
            int root_start = 0, root_end = 0;
            int target_start = 0, target_end = 0;
            int vfs_option_start = 0, vfs_option_end = 0;
            int type_start = 0, type_end = 0;
            int source_start = 0, source_end = 0;
            int fs_option_start = 0, fs_option_end = 0;
            int optional_start = 0, optional_end = 0;
            unsigned int id, parent, maj, min;
            sscanf(line.data(),
                   "%u "           // (1) id
                   "%u "           // (2) parent
                   "%u:%u "        // (3) maj:min
                   "%n%*s%n "      // (4) mountroot
                   "%n%*s%n "      // (5) target
                   "%n%*s%n"       // (6) vfs options (fs-independent)
                   "%n%*[^-]%n - " // (7) optional fields
                   "%n%*s%n "      // (8) FS type
                   "%n%*s%n "      // (9) source
                   "%n%*s%n",      // (10) fs options (fs specific)
                   &id, &parent, &maj, &min, &root_start, &root_end, &target_start,
                   &target_end, &vfs_option_start, &vfs_option_end,
                   &optional_start, &optional_end, &type_start, &type_end,
                   &source_start, &source_end, &fs_option_start, &fs_option_end);

            auto root = line.substr(root_start, root_end - root_start);
            auto target = line.substr(target_start, target_end - target_start);
            auto vfs_option =
                    line.substr(vfs_option_start, vfs_option_end - vfs_option_start);
            ++optional_start;
            --optional_end;
            auto optional = line.substr(
                    optional_start,
                    optional_end - optional_start > 0 ? optional_end - optional_start : 0);

            auto type = line.substr(type_start, type_end - type_start);
            auto source = line.substr(source_start, source_end - source_start);
            auto fs_option =
                    line.substr(fs_option_start, fs_option_end - fs_option_start);

            unsigned int shared = 0;
            unsigned int master = 0;
            unsigned int propagate_from = 0;
            if (auto pos = optional.find("shared:"); pos != std::string_view::npos) {
                shared = parse_num(optional.substr(pos + 7));
            }
            if (auto pos = optional.find("master:"); pos != std::string_view::npos) {
                master = parse_num(optional.substr(pos + 7));
            }
            if (auto pos = optional.find("propagate_from:");
                    pos != std::string_view::npos) {
                propagate_from = parse_num(optional.substr(pos + 15));
            }

            info.emplace_back(MountInfo{
                    .id = id,
                    .parent = parent,
                    .device = static_cast<dev_t>(makedev(maj, min)),
                    .root {root},
                    .target {target},
                    .vfs_option {vfs_option},
                    .optional {
                            .shared = shared,
                            .master = master,
                            .propagate_from = propagate_from,
                    },
                    .type {type},
                    .source {source},
                    .fs_option {fs_option},
            });
        }
        free(buf);
    }
    return info;
}

std::string MountInfo::ToMounts() const {
    //todo: fs_option与vfs_option需要合并重排，修正rw状态
    return source + " " + target + " " + type + " " + vfs_option + "," + fs_option +
           " 0 0\n";
}

} // namespace proc_util::inline v2

