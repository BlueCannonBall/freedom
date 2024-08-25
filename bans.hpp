#pragma once

#include "Polyweb/Polynet/string.hpp"
#include <string>
#include <vector>

namespace bans {
    void init();
    std::vector<std::string> get_all_bans();
    void ban(pn::StringView username);
    void unban(pn::StringView username);
    bool is_banned(pn::StringView username);
} // namespace bans
