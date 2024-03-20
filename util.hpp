#pragma once

#include "Polyweb/Polynet/polynet.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#ifndef _WIN32
    #include <sys/time.h>
#endif

#define CONNECTION_CLOSE \
    { "Connection", "close" }
#define PROXY_CONNECTION_CLOSE \
    { "Proxy-Connection", "close" }
#define PROXY_AUTHENTICATE_BASIC \
    { "Proxy-Authenticate", "basic" }

#define INFO(message)                                           \
    {                                                           \
        std::cout << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Info: " << message << std::endl;          \
    }
#define ERR(message)                                            \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Error: " << message << std::endl;         \
    }
#define ERR_NET                                                                  \
    {                                                                            \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] "                  \
                  << "Network error: " << pn::universal_strerror() << std::endl; \
    }
#define ERR_WEB                                                 \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << pw::universal_strerror() << std::endl;     \
    }
#define ERR_CLI(message)                                        \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "CLI error: " << message << std::endl;     \
    }

inline int configure_socket(pn::Socket& socket) {
    static constexpr int value = 1;
    if (socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#ifdef __linux__
    if (socket.setsockopt(IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#endif
    if (socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

inline int set_socket_timeout(pn::Socket& socket, std::chrono::milliseconds timeout_duration) {
#ifdef _WIN32
    DWORD timeout = timeout_duration.count();
#else
    struct timeval timeout;
    timeout.tv_sec = timeout_duration.count() / 1000;
    timeout.tv_usec = (timeout_duration.count() % 1000) * 1000;
#endif
    if (socket.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) == PN_ERROR) {
        return PN_ERROR;
    }
    if (socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

inline std::string get_date(time_t rawtime = time(nullptr)) {
#ifdef _WIN32
    struct tm timeinfo = *localtime(&rawtime);
#else
    struct tm timeinfo;
    localtime_r(&rawtime, &timeinfo);
#endif
    std::ostringstream ss;
    ss.imbue(std::locale("C"));
    ss << std::put_time(&timeinfo, "%y/%m/%d");
    return ss.str();
}

template <typename Clock = std::chrono::steady_clock, typename DoneCallback = std::function<void(typename Clock::duration)>>
class Timer {
protected:
    typename Clock::time_point start_time;
    DoneCallback done_cb;

public:
    Timer() = default;
    Timer(DoneCallback done_cb):
        start_time(Clock::now()),
        done_cb(done_cb) {}
    Timer(Timer&& timer) {
        *this = std::move(timer);
    }

    Timer& operator=(Timer&& timer) {
        if (this != &timer) {
            reset(timer.done_cb);
            timer.done_cb = DoneCallback();
        }
        return *this;
    }

    ~Timer() {
        done();
    }

    void done() {
        if (done_cb) {
            done_cb(Clock::now() - start_time);
            done_cb = DoneCallback();
        }
    }

    void reset(DoneCallback done_cb) {
        done();
        start_time = Clock::now();
        done_cb = std::move(done_cb);
    }

    DoneCallback release() {
        return std::exchange(done_cb, DoneCallback());
    }
};
