#pragma once

#include <string>

namespace adblock {
    void register_blacklist(const std::string& url, const std::string& reason);
    void unregister_blacklist(const std::string& url);
    void update_all_blacklists();
    bool is_blacklisted(const std::string& hostname, std::string& reason);
} // namespace adblock
