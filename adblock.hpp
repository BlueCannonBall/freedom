#pragma once

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace adblock {
    const extern char* const blocked_hostnames[];
    const extern size_t blocked_hostname_count;
    extern std::set<std::hash<std::string>::result_type> blocked_hostname_hashes;
    extern thread_local std::hash<std::string> hostname_hasher;

    inline void init() {
        for (size_t i = 0; i < blocked_hostname_count; i++) {
            blocked_hostname_hashes.insert(hostname_hasher(blocked_hostnames[i]));
        }
    }

    inline void quit() {
        blocked_hostname_hashes.clear();
    }

    inline bool check_hostname(const std::string& hostname) {
        return blocked_hostname_hashes.count(hostname_hasher(hostname));
    }
} // namespace adblock