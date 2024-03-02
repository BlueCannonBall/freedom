#pragma once

#include <string>

namespace adblock {
    // This function is not thread-safe
    void init();

    bool check_hostname(const std::string& hostname);
} // namespace adblock
