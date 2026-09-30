#ifndef _LOGGING_H
#define _LOGGING_H

#include <android/log.h>
#include <fmt/format.h>
#include <array>
#include <cerrno>
#include <cstring>

#ifndef LOG_TAG
#define LOG_TAG    "TrustAttestorLog"
#endif

#ifdef NDEBUG
#define LOGD(...) 0
#define LOGV(...) 0
#define LOGI(...) 0
#define LOGW(...) 0
#define LOGE(...) 0
#define PLOGE(...) 0
#else
template <typename... T>
constexpr inline void LOG(int prio, const char* tag, fmt::format_string<T...> fmt, T&&... args) {
    std::array<char, 1024> buf{};
    auto s = fmt::format_to_n(buf.data(), buf.size(), fmt, std::forward<T>(args)...).size;
    if (s >= 1024) s = 1023;
    buf[s] = '\0';
    __android_log_write(prio, tag, buf.data());
}
#define LOGD(fmt, ...) LOG(ANDROID_LOG_DEBUG, LOG_TAG, "{}:{}#{}" ": " fmt, __FILE_NAME__, __LINE__, __PRETTY_FUNCTION__ __VA_OPT__(,) __VA_ARGS__)
#define LOGV(fmt, ...) LOG(ANDROID_LOG_VERBOSE, LOG_TAG, "{}:{}#{}" ": " fmt, __FILE_NAME__, __LINE__, __PRETTY_FUNCTION__ __VA_OPT__(,) __VA_ARGS__)
#define LOGI(...)  LOG(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...)  LOG(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  LOG(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, ...)  LOG(ANDROID_LOG_ERROR, LOG_TAG, fmt " failed with {} {}" __VA_OPT__(,) __VA_ARGS__, errno, strerror(errno))
#endif

#endif // _LOGGING_H
