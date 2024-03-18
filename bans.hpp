#pragma once

#include <set>
#include <string>

std::set<std::string> get_bans();
void set_bans(const std::set<std::string>& bans);
