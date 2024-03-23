#include "adblock.hpp"
#include "Polyweb/polyweb.hpp"
#include <chrono>
#include <mutex>
#include <sstream>
#include <unordered_set>

namespace adblock {
    std::mutex mutex;
    std::unordered_set<std::string> blocked_hostnames;
    std::chrono::steady_clock::time_point last_updated = std::chrono::steady_clock::time_point::min();

    void init() {
        if (std::chrono::steady_clock::now() - last_updated > std::chrono::hours(24)) {
            pw::HTTPResponse resp;
            if (pw::fetch("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt", resp, {}, {.body_rlimit = 100'000'000}) == PN_OK &&
                resp.status_code_category() == 200) {
                blocked_hostnames.clear();
                std::istringstream ss(resp.body_string());
                for (std::string line; std::getline(ss, line);) {
                    pw::string::trim(line);
                    if (!line.empty() && line.front() != '#') {
                        blocked_hostnames.insert(std::move(line));
                    }
                }
            }
            last_updated = std::chrono::steady_clock::now();
        }
    }

    bool check_hostname(const std::string& hostname) {
        std::lock_guard<std::mutex> lock(mutex);
        init();
        return blocked_hostnames.count(hostname);
    }
} // namespace adblock
