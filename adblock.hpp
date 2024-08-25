#pragma once

#include "Polyweb/Polynet/string.hpp"
#include <string>

namespace adblock {
    void register_blacklist(const std::string& url, pn::StringView reason);
    void unregister_blacklist(const std::string& url);
    void update_all_blacklists();
    bool is_blacklisted(const std::string& hostname, std::string& reason, bool update_lists = true);
} // namespace adblock
