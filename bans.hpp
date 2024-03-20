#pragma once

#include "sqlite.hpp"
#include <string>
#include <vector>

extern sqlite::Connection ban_db;

void init_ban_table();
std::vector<std::string> get_bans();

void ban(const std::string& username);
void unban(const std::string& username);
bool is_banned(const std::string& username);
