#pragma once

#include <functional>
#include <string>
#include <unordered_set>

namespace adblock {
    const extern char* const blocked_hostnames[];
    const extern size_t blocked_hostname_count;
    extern std::hash<std::string> hostname_hasher;
    extern std::unordered_set<size_t> blocked_hostname_hashes;

    inline void init() {
        for (size_t i = 0; i < blocked_hostname_count; ++i) {
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
