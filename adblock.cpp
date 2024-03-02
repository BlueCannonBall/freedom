#include "adblock.hpp"
#include "Polyweb/polyweb.hpp"
#include <ctime>
#include <mutex>
#include <sstream>
#include <unordered_set>

namespace adblock {
    namespace detail {
        std::mutex update_mutex;
        std::unordered_set<std::string> blocked_hostnames;
        time_t last_updated = 0;
    } // namespace detail

    void init() {
        if (time(nullptr) - detail::last_updated > 86400) {
            pw::HTTPResponse resp;
            if (pw::fetch("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt", resp, {}, {.body_rlimit = 100'000'000}) == PN_OK &&
                resp.status_code_category() == 200) {
                detail::blocked_hostnames.clear();
                std::istringstream ss(resp.body_string());
                for (std::string line; std::getline(ss, line);) {
                    pw::string::trim(line);
                    if (!line.empty() && line.front() != '#') {
                        detail::blocked_hostnames.insert(std::move(line));
                    }
                }
            }
            detail::last_updated = time(nullptr);
        }
    }

    bool check_hostname(const std::string& hostname) {
        std::lock_guard<std::mutex> lock(detail::update_mutex);
        init();
        return detail::blocked_hostnames.count(hostname);
    }
} // namespace adblock
