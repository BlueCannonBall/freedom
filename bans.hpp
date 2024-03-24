#pragma once

#include <string>
#include <vector>

namespace bans {
    void init();
    std::vector<std::string> get_all_bans();

    void ban(const std::string& username);
    void unban(const std::string& username);
    bool is_banned(const std::string& username);
} // namespace bans
