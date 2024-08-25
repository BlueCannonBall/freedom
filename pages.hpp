#pragma once

#include "Polyweb/polyweb.hpp"
#include <chrono>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

namespace pages {
    extern std::mutex stats_mutex;
    extern const time_t running_since;
    extern unsigned long long requests_handled;
    extern unsigned long long ads_blocked;
    extern std::chrono::milliseconds response_time;
    extern std::unordered_map<std::string, unsigned long long> users;
    extern std::map<std::string, unsigned long long> activity;

    pw::HTTPResponse stats_page(pn::StringView http_version = "HTTP/1.1");
    pw::HTTPResponse error_page(uint16_t status_code, pn::StringView host, pn::StringView error_message, pn::StringView http_version = "HTTP/1.1");
} // namespace pages
