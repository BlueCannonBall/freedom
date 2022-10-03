#pragma once

#include <set>
#include <string>
#include <vector>

namespace adblock {
    extern std::set<std::string> blocked_hostnames;
    const extern std::vector<const char*> blocked_hostnames_raw;

    inline void init() {
        blocked_hostnames.insert(blocked_hostnames_raw.begin(), blocked_hostnames_raw.end());
    }

    inline void quit() {
        blocked_hostnames.clear();
    }

    inline bool check_hostname(const std::string& hostname) {
        return blocked_hostnames.count(hostname);
    }
} // namespace adblock