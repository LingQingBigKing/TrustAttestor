#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "checker_internal.h"
#include "logging.h"
#include "proc_util.hpp"

// Detection-only module. Finding serialization and all JNI/UI interaction stay
// in checker.cpp.

namespace runtime_probe {

Evidence evidence;

namespace {

constexpr uint16_t kFridaDefaultPort = 27042;
constexpr int kConnectTimeoutMs = 220;
constexpr int kResponseTimeoutMs = 280;
constexpr size_t kMaximumResponse = 4096;

enum class EndpointResult {
    Closed,
    Open,
    WebSocketFingerprint,
};

std::string Lower(std::string_view source) {
    std::string output(source);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return output;
}

bool HeaderContainsToken(
        const std::string& lower_response,
        std::string_view header_name,
        std::string_view token) {
    const size_t status_end = lower_response.find("\r\n");
    if (status_end == std::string::npos) return false;
    size_t line_start = status_end + 2;
    while (line_start != std::string::npos && line_start < lower_response.size()) {
        const size_t line_end = lower_response.find("\r\n", line_start);
        if (line_end == std::string::npos || line_end == line_start) break;
        const std::string_view line(lower_response.data() + line_start, line_end - line_start);
        if (line.starts_with(header_name)) {
            const std::string_view value = line.substr(header_name.size());
            size_t begin = 0;
            while (begin < value.size()) {
                const size_t comma = value.find(',', begin);
                const size_t end = comma == std::string_view::npos ? value.size() : comma;
                size_t first = begin;
                size_t last = end;
                while (first < last && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
                while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
                if (value.substr(first, last - first) == token) return true;
                if (comma == std::string_view::npos) break;
                begin = comma + 1;
            }
        }
        line_start = line_end + 2;
    }
    return false;
}

std::string Basename(std::string_view path) {
    auto slash = path.find_last_of('/');
    return std::string(path.substr(slash == std::string_view::npos ? 0 : slash + 1));
}

void AddUnique(std::vector<std::string>& output, std::string value) {
    if (value.empty()) return;
    if (std::find(output.begin(), output.end(), value) == output.end()) {
        output.emplace_back(std::move(value));
    }
}

std::string ReadBoundedFile(const std::string& path, size_t maximum) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::string output(maximum, '\0');
    size_t used = 0;
    while (used < maximum) {
        ssize_t length = read(fd, output.data() + used, maximum - used);
        if (length > 0) {
            used += static_cast<size_t>(length);
            continue;
        }
        if (length < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);
    output.resize(used);
    return output;
}

bool WaitForFd(int fd, short events, int timeout_ms) {
    pollfd descriptor{fd, events, 0};
    int result;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    return result > 0 && (descriptor.revents & events) != 0 &&
           (descriptor.revents & (POLLERR | POLLNVAL)) == 0;
}

bool SendAll(int fd, const char* data, size_t size) {
    size_t sent = 0;
    const uint64_t deadline = MonotonicMillis() + kResponseTimeoutMs;
    while (sent < size) {
        ssize_t current = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (current > 0) {
            sent += static_cast<size_t>(current);
            continue;
        }
        if (current < 0 && errno == EINTR) continue;
        if (current < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const uint64_t now = MonotonicMillis();
            if (now >= deadline || !WaitForFd(fd, POLLOUT, static_cast<int>(deadline - now))) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

std::string ReceiveHttpHeaders(int fd) {
    std::string response;
    response.reserve(1024);
    const uint64_t deadline = MonotonicMillis() + kResponseTimeoutMs;
    while (response.size() < kMaximumResponse) {
        const uint64_t now = MonotonicMillis();
        if (now >= deadline || !WaitForFd(fd, POLLIN, static_cast<int>(deadline - now))) break;
        std::array<char, 1024> buffer{};
        ssize_t length = recv(fd, buffer.data(), buffer.size(), 0);
        if (length > 0) {
            response.append(buffer.data(), static_cast<size_t>(length));
            if (response.find("\r\n\r\n") != std::string::npos) break;
            continue;
        }
        if (length < 0 && errno == EINTR) continue;
        if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        break;
    }
    return response;
}

EndpointResult ProbeFridaEndpoint(std::string& protocol_evidence) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return EndpointResult::Closed;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return EndpointResult::Closed;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(kFridaDefaultPort);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int connected = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (connected != 0 && errno != EINPROGRESS) {
        close(fd);
        return EndpointResult::Closed;
    }
    if (connected != 0 && !WaitForFd(fd, POLLOUT, kConnectTimeoutMs)) {
        close(fd);
        return EndpointResult::Closed;
    }

    int socket_error = 0;
    socklen_t error_size = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_size) != 0 ||
        socket_error != 0) {
        close(fd);
        return EndpointResult::Closed;
    }

    // RFC 6455 sample nonce has a fixed, independently known accept value. An
    // open TCP port alone is never treated as a Frida finding.
    static constexpr char kRequest[] =
            "GET /ws HTTP/1.1\r\n"
            "Host: 127.0.0.1:27042\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
    if (!SendAll(fd, kRequest, sizeof(kRequest) - 1)) {
        close(fd);
        protocol_evidence = "127.0.0.1:27042 accepted TCP but closed during protocol challenge";
        return EndpointResult::Open;
    }

    std::string response = ReceiveHttpHeaders(fd);
    close(fd);
    const std::string lower = Lower(response);
    const bool switching_protocols = lower.starts_with("http/1.1 101 ") ||
                                     lower.starts_with("http/1.0 101 ");
    const bool websocket_upgrade = HeaderContainsToken(lower, "upgrade:", "websocket");
    const bool connection_upgrade = HeaderContainsToken(lower, "connection:", "upgrade");
    const bool accept_matches = lower.find(
            "sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=") != std::string::npos;
    if (switching_protocols && websocket_upgrade && connection_upgrade && accept_matches) {
        protocol_evidence =
                "127.0.0.1:27042/ws returned HTTP 101 with the expected RFC6455 accept value";
        return EndpointResult::WebSocketFingerprint;
    }

    protocol_evidence = "127.0.0.1:27042 accepted TCP; Frida WebSocket fingerprint not matched";
    return EndpointResult::Open;
}

bool ContainsStrongFridaMarker(std::string_view source) {
    const std::string lower = Lower(source);
    static constexpr std::string_view kMarkers[] = {
            "gum-js-loop",
            "pool-frida",
            "frida-agent",
            "frida-gadget",
            "libfrida-gadget",
            "linjector",
            "re.frida.server",
    };
    for (auto marker : kMarkers) {
        if (lower.find(marker) != std::string::npos) return true;
    }
    return false;
}

std::vector<std::string> ScanFridaRuntimeMarkers() {
    std::vector<std::string> markers;
    const std::string maps = ReadBoundedFile("/proc/self/maps", 4 * 1024 * 1024);
    size_t line_start = 0;
    while (line_start < maps.size()) {
        const size_t line_end = maps.find('\n', line_start);
        const size_t length = (line_end == std::string::npos ? maps.size() : line_end) - line_start;
        const std::string_view line(maps.data() + line_start, length);
        if (ContainsStrongFridaMarker(line)) {
            AddUnique(markers, "map=" + std::string(line.substr(0, std::min<size_t>(line.size(), 240))));
            if (markers.size() >= 8) break;
        }
        if (line_end == std::string::npos) break;
        line_start = line_end + 1;
    }

    DIR* tasks = opendir("/proc/self/task");
    if (tasks != nullptr) {
        while (dirent* entry = readdir(tasks)) {
            if (entry->d_name[0] == '.') continue;
            std::string name = ReadBoundedFile(
                    std::string("/proc/self/task/") + entry->d_name + "/comm", 256);
            while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
            if (ContainsStrongFridaMarker(name)) {
                AddUnique(markers, std::string("thread=") + entry->d_name + ":" + name);
            }
        }
        closedir(tasks);
    }

    DIR* descriptors = opendir("/proc/self/fd");
    if (descriptors != nullptr) {
        while (dirent* entry = readdir(descriptors)) {
            if (entry->d_name[0] == '.') continue;
            std::string path = std::string("/proc/self/fd/") + entry->d_name;
            std::array<char, PATH_MAX + 1> target{};
            ssize_t length = readlink(path.c_str(), target.data(), PATH_MAX);
            if (length <= 0) continue;
            std::string value(target.data(), static_cast<size_t>(length));
            if (ContainsStrongFridaMarker(value)) {
                AddUnique(markers, std::string("fd=") + entry->d_name + ":" + value);
            }
        }
        closedir(descriptors);
    }
    return markers;
}

struct ApiExpectation {
    const char* symbol;
    std::set<std::string> allowedModules;
};

const proc_util::MapInfo* FindAddressMap(
        uintptr_t address,
        const std::vector<proc_util::MapInfo>& maps) {
    for (const auto& map : maps) {
        if (address >= map.start && address < map.end) return &map;
    }
    return nullptr;
}

std::string DescribeOwner(
        const char* symbol,
        const proc_util::MapInfo* map,
        const char* dl_path) {
    std::string output(symbol);
    output += " -> map=";
    output += map == nullptr ? "<none>" : map->path;
    output += ", dladdr=";
    output += dl_path == nullptr ? "<none>" : dl_path;
    return output;
}

void CheckNativeApiOwners() {
    const std::vector<ApiExpectation> expectations = {
            {"open", {"libc.so"}},
            {"read", {"libc.so"}},
            {"mmap", {"libc.so"}},
            {"mprotect", {"libc.so"}},
            {"dlopen", {"libdl.so", "libc.so", "linker", "linker64"}},
            {"dlsym", {"libdl.so", "libc.so", "linker", "linker64"}},
    };

    const auto maps = proc_util::MapInfo::Scan();
    if (maps.empty()) {
        evidence.apiOwnerUnavailable.emplace_back("/proc/self/maps inventory is unavailable");
        MarkRuntimeIntegrity(NATIVE_API_OWNER_INCOMPLETE);
        return;
    }

    for (const auto& expected : expectations) {
        dlerror();
        void* address = dlsym(RTLD_DEFAULT, expected.symbol);
        const char* resolve_error = dlerror();
        if (address == nullptr || resolve_error != nullptr) {
            AddUnique(evidence.apiOwnerUnavailable,
                      std::string(expected.symbol) + " could not be resolved");
            continue;
        }

        const uintptr_t pointer = reinterpret_cast<uintptr_t>(address);
        const proc_util::MapInfo* map = FindAddressMap(pointer, maps);
        Dl_info info{};
        const bool has_dl_info = dladdr(address, &info) != 0 && info.dli_fname != nullptr;
        const std::string map_module = map == nullptr ? std::string() : Basename(map->path);
        const std::string dl_module = has_dl_info ? Basename(info.dli_fname) : std::string();
        const std::string description = DescribeOwner(
                expected.symbol, map, has_dl_info ? info.dli_fname : nullptr);

        if (map == nullptr || (map->perms & PROT_EXEC) == 0 || map->path.empty() ||
            map->path.front() != '/' || expected.allowedModules.count(map_module) == 0) {
            AddUnique(evidence.apiOwnerMismatches, description);
            continue;
        }
        if (has_dl_info && !dl_module.empty() && dl_module != map_module) {
            AddUnique(evidence.apiOwnerMismatches, description + ", resolver/map disagreement");
            continue;
        }

        struct stat file_stat{};
        if (stat(map->path.c_str(), &file_stat) != 0) {
            AddUnique(evidence.apiOwnerUnavailable, description + ", backing file cannot be stat'ed");
            continue;
        }
        if (map->inode == 0 || file_stat.st_ino != map->inode || file_stat.st_dev != map->dev) {
            AddUnique(evidence.apiOwnerMismatches, description + ", inode/device identity mismatch");
            continue;
        }
        AddUnique(evidence.apiOwnerVerified, description);
    }

    if (!evidence.apiOwnerMismatches.empty()) {
        MarkRuntimeIntegrity(NATIVE_API_OWNER_MISMATCH);
    }
    if (!evidence.apiOwnerUnavailable.empty()) {
        MarkRuntimeIntegrity(NATIVE_API_OWNER_INCOMPLETE);
    }
}

}  // namespace

void Reset() {
    sRuntimeIntegrity = 0;
    evidence = Evidence{};
}

void Run() {
    std::string endpoint_evidence;
    const EndpointResult endpoint = ProbeFridaEndpoint(endpoint_evidence);
    evidence.fridaProtocol = std::move(endpoint_evidence);
    if (endpoint == EndpointResult::WebSocketFingerprint) {
        LOGE("Frida-compatible WebSocket endpoint detected on 127.0.0.1:27042/ws");
        MarkRuntimeIntegrity(FRIDA_PROTOCOL);
    } else if (endpoint == EndpointResult::Open) {
        LOGW("Port 27042 is open but the Frida protocol fingerprint did not match");
        MarkRuntimeIntegrity(FRIDA_PORT_OPEN);
    }

    evidence.fridaRuntime = ScanFridaRuntimeMarkers();
    if (!evidence.fridaRuntime.empty()) {
        LOGE("Strong Frida runtime markers detected: {}", evidence.fridaRuntime.size());
        MarkRuntimeIntegrity(FRIDA_RUNTIME_MARKER);
    }

    CheckNativeApiOwners();
    MarkRuntimeIntegrity(CHECK_COMPLETED);
}

}  // namespace runtime_probe
