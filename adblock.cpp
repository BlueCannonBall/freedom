#include "adblock.hpp"
#include "Polyweb/polyweb.hpp"
#include <chrono>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace adblock {
    class Blacklist {
    protected:
        std::unordered_set<std::string> hostnames;
        std::chrono::steady_clock::time_point last_updated;

    public:
        std::string reason;

        Blacklist() = default;
        Blacklist(pn::StringView reason):
            reason(reason) {}

        void update(pn::StringView url) {
            auto now = std::chrono::steady_clock::now();
            if (hostnames.empty() || now - last_updated > std::chrono::hours(24)) {
                pw::HTTPResponse resp;
                if (pw::fetch(url, resp, {}, {.body_rlimit = 100'000'000}) == PN_OK &&
                    resp.status_code_category() == 200) {
                    hostnames.clear();
                    std::istringstream ss(resp.body_string());
                    for (std::string line; std::getline(ss, line);) {
                        pw::string::trim(line);
                        if (pw::string::starts_with(line, "0.0.0.0 ")) {
                            line.erase(0, 8);
                        }
                        if (!line.empty() && line.front() != '#') {
                            hostnames.insert(std::move(line));
                        }
                    }
                }
                last_updated = now;
            }
        }

        bool is_blacklisted(const std::string& hostname) const {
            return hostnames.count(hostname);
        }
    };

    std::mutex mutex;
    std::unordered_map<std::string, Blacklist> blacklists;

    void register_blacklist(const std::string& url, pn::StringView reason) {
        std::lock_guard<std::mutex> lock(mutex);
        blacklists[url] = Blacklist(reason);
    }

    void unregister_blacklist(const std::string& url) {
        std::lock_guard<std::mutex> lock(mutex);
        blacklists.erase(url);
    }

    void update_all_blacklists() {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& blacklist : blacklists) {
            blacklist.second.update(blacklist.first);
        }
    }

    bool is_blacklisted(const std::string& hostname, std::string& reason, bool update_lists) {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& blacklist : blacklists) {
            if (update_lists) blacklist.second.update(blacklist.first);
            if (blacklist.second.is_blacklisted(hostname)) {
                reason = blacklist.second.reason;
                return true;
            }
        }
        return false;
    }
} // namespace adblock
