#pragma once

#include <mutex>
#include <set>
#include <string>

extern std::mutex ban_mutex;

std::set<std::string> get_bans();
void set_bans(const std::set<std::string>& bans);
