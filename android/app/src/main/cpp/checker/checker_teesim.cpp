#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>

#include "checker_internal.h"
#include "logging.h"

namespace teesim_probe {

constexpr int ADMIN_PORT = 8790;
constexpr int IO_TIMEOUT_MS = 600;
constexpr size_t MAX_HTTP_RESPONSE = 8192;

struct HttpResponse {
    std::string statusLine;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

static std::string TrimAscii(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

static std::string LowerAscii(std::string_view value) {
    std::string lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

static bool ParseHttpResponse(const std::string& raw, HttpResponse& response) {
    const size_t headerEnd = raw.find("\r\n\r\n");
    if (headerEnd == std::string::npos) return false;

    const size_t statusEnd = raw.find("\r\n");
    if (statusEnd == std::string::npos || statusEnd >= headerEnd) return false;
    response.statusLine = raw.substr(0, statusEnd);
    response.headers.clear();

    size_t cursor = statusEnd + 2;
    while (cursor < headerEnd) {
        const size_t lineEnd = raw.find("\r\n", cursor);
        if (lineEnd == std::string::npos || lineEnd > headerEnd) return false;
        const std::string_view line(raw.data() + cursor, lineEnd - cursor);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) return false;
        response.headers[LowerAscii(TrimAscii(line.substr(0, colon)))] =
                TrimAscii(line.substr(colon + 1));
        cursor = lineEnd + 2;
    }

    response.body.assign(raw.data() + headerEnd + 4, raw.size() - headerEnd - 4);
    return true;
}

static bool ParseContentLength(const HttpResponse& response, size_t& length) {
    auto it = response.headers.find("content-length");
    if (it == response.headers.end() || it->second.empty()) return false;
    size_t parsed = 0;
    for (unsigned char ch : it->second) {
        if (ch < '0' || ch > '9') return false;
        if (parsed > (MAX_HTTP_RESPONSE - static_cast<size_t>(ch - '0')) / 10) return false;
        parsed = parsed * 10 + static_cast<size_t>(ch - '0');
    }
    length = parsed;
    return true;
}

static bool IsHttpMessageComplete(const std::string& raw) {
    HttpResponse response;
    size_t contentLength = 0;
    return ParseHttpResponse(raw, response) &&
           ParseContentLength(response, contentLength) &&
           response.body.size() >= contentLength;
}

static bool WaitForSocket(int fd, short events, uint64_t deadline) {
    for (;;) {
        const uint64_t now = MonotonicMillis();
        if (now >= deadline) return false;
        pollfd descriptor{fd, events, 0};
        const int timeout = static_cast<int>(std::min<uint64_t>(deadline - now, INT_MAX));
        const int ready = poll(&descriptor, 1, timeout);
        if (ready > 0) return (descriptor.revents & (events | POLLHUP | POLLERR)) != 0;
        if (ready == 0) return false;
        if (errno != EINTR) return false;
    }
}

static int ConnectAdminSocket() {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return -1;

    const int originalFlags = fcntl(fd, F_GETFL, 0);
    if (originalFlags < 0 || fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(ADMIN_PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
        const uint64_t deadline = MonotonicMillis() + IO_TIMEOUT_MS;
        if (!WaitForSocket(fd, POLLOUT, deadline)) {
            close(fd);
            return -1;
        }
        int socketError = 0;
        socklen_t errorLength = sizeof(socketError);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) < 0 ||
            socketError != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static bool SendAll(int fd, std::string_view request, uint64_t deadline) {
    size_t sent = 0;
    while (sent < request.size()) {
        if (!WaitForSocket(fd, POLLOUT, deadline)) return false;
        const ssize_t count = send(fd, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return false;
    }
    return true;
}

static bool ReceiveResponse(int fd, std::string& raw, uint64_t deadline) {
    std::array<char, 1024> buffer{};
    raw.clear();
    while (raw.size() < MAX_HTTP_RESPONSE) {
        if (!WaitForSocket(fd, POLLIN, deadline)) return IsHttpMessageComplete(raw);
        const size_t remaining = MAX_HTTP_RESPONSE - raw.size();
        const ssize_t count = recv(fd, buffer.data(), std::min(buffer.size(), remaining), 0);
        if (count > 0) {
            raw.append(buffer.data(), static_cast<size_t>(count));
            if (IsHttpMessageComplete(raw)) return true;
            continue;
        }
        if (count == 0) return IsHttpMessageComplete(raw);
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return false;
    }
    return IsHttpMessageComplete(raw);
}

static bool RequestAdmin(std::string_view method, std::string_view path, HttpResponse& response) {
    const int fd = ConnectAdminSocket();
    if (fd < 0) return false;

    std::string request;
    request.reserve(method.size() + path.size() + 64);
    request.append(method);
    request.push_back(' ');
    request.append(path);
    request.append(" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");

    const uint64_t deadline = MonotonicMillis() + IO_TIMEOUT_MS;
    std::string raw;
    const bool exchanged = SendAll(fd, request, deadline) && ReceiveResponse(fd, raw, deadline);
    close(fd);
    return exchanged && ParseHttpResponse(raw, response);
}

static bool HeaderEquals(
        const HttpResponse& response,
        std::string_view name,
        std::string_view expected) {
    auto it = response.headers.find(std::string(name));
    return it != response.headers.end() && it->second == expected;
}

static std::string MakeProbePath() {
    static std::atomic_uint64_t sequence{0};
    return fmt::format(
            "/_teesim_probe_{:x}_{:x}_{:x}",
            static_cast<uint64_t>(getpid()),
            MonotonicMillis(),
            sequence.fetch_add(1, std::memory_order_relaxed));
}

static bool ProbeAdminProtocol() {
    const std::string path = MakeProbePath();
    HttpResponse options;
    if (!RequestAdmin("OPTIONS", path, options)) return false;
    const bool optionsMatch =
            options.statusLine == "HTTP/1.1 204 No Content" &&
            HeaderEquals(options, "content-type", "application/json") &&
            HeaderEquals(options, "content-length", "0") &&
            HeaderEquals(options, "access-control-allow-origin", "*") &&
            HeaderEquals(options, "access-control-allow-headers", "X-Teesim-Token, Content-Type") &&
            HeaderEquals(options, "access-control-allow-methods", "GET, POST, OPTIONS") &&
            HeaderEquals(options, "connection", "close") &&
            options.body.empty();
    if (!optionsMatch) return false;

    HttpResponse get;
    if (!RequestAdmin("GET", path, get)) return false;
    return get.statusLine == "HTTP/1.1 403 Forbidden" &&
           HeaderEquals(get, "content-type", "application/json") &&
           HeaderEquals(get, "content-length", "36") &&
           HeaderEquals(get, "connection", "close") &&
           get.body == "{\"ok\":false,\"error\":\"invalid token\"}";
}

enum class AbstractBindResult {
    BOUND,
    IN_USE,
    UNAVAILABLE,
};

static AbstractBindResult TryBindAbstract(std::string_view name) {
    if (name.empty() || name.size() + 1 > sizeof(sockaddr_un::sun_path)) {
        return AbstractBindResult::UNAVAILABLE;
    }

    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return AbstractBindResult::UNAVAILABLE;

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name.data(), name.size());
    const socklen_t length = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + 1 + name.size());
    const int result = TEMP_FAILURE_RETRY(
            bind(fd, reinterpret_cast<sockaddr*>(&address), length));
    const int bindError = result == 0 ? 0 : errno;
    close(fd);
    if (result == 0) return AbstractBindResult::BOUND;
    if (bindError == EADDRINUSE) return AbstractBindResult::IN_USE;
    LOGI("TEESimulator abstract socket bind unavailable: errno={} ({})",
         bindError, strerror(bindError));
    return AbstractBindResult::UNAVAILABLE;
}

static bool ProbeControlSocket() {
    static std::atomic_uint64_t sequence{0};
    const std::string calibration = fmt::format(
            "teesim_probe_{:x}_{:x}_{:x}",
            static_cast<uint64_t>(getpid()),
            MonotonicMillis(),
            sequence.fetch_add(1, std::memory_order_relaxed));
    if (TryBindAbstract(calibration) != AbstractBindResult::BOUND) return false;

    const AbstractBindResult first = TryBindAbstract("teesim");
    msleep(40);
    const AbstractBindResult second = TryBindAbstract("teesim");
    if (first == AbstractBindResult::UNAVAILABLE || second == AbstractBindResult::UNAVAILABLE) {
        return false;
    }
    return first == AbstractBindResult::IN_USE && second == AbstractBindResult::IN_USE;
}

static bool ProbeRsSoterProtocol(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) return false;
    auto probe_class = env->FindClass("com/lingqing/trustattestor/SoterRsProbe");
    if (probe_class == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("TEESimulator-RS SOTER probe class unavailable");
        return false;
    }
    auto probe_method = env->GetStaticMethodID(
            probe_class, "probe", "(Landroid/content/Context;)Z");
    if (probe_method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(probe_class);
        LOGE("TEESimulator-RS SOTER probe method unavailable");
        return false;
    }
    auto matched = env->CallStaticBooleanMethod(probe_class, probe_method, context);
    env->DeleteLocalRef(probe_class);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("TEESimulator-RS SOTER probe invocation failed");
        return false;
    }
    return matched == JNI_TRUE;
}

}  // namespace teesim_probe

void FindTeeSimulator(JNIEnv* env, jobject context) {
    if (teesim_probe::ProbeAdminProtocol()) {
        LOGE("TEESimulator v4 admin protocol fingerprint matched on 127.0.0.1:8790");
        MarkTeeSimulator(teesim_probe::ADMIN_PROTOCOL);
    }
    if (teesim_probe::ProbeControlSocket()) {
        LOGE("TEESimulator control socket @teesim is occupied");
        MarkTeeSimulator(teesim_probe::CONTROL_SOCKET);
    }
    if (teesim_probe::ProbeRsSoterProtocol(env, context)) {
        LOGE("TEESimulator-RS forged SOTER getDeviceId response matched");
        MarkTeeSimulator(teesim_probe::RS_SOTER_PROTOCOL);
    }
}
