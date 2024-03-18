#include "bans.hpp"
#include <fstream>

std::set<std::string> get_bans() {
    std::set<std::string> ret;
    std::ifstream file("bans.txt");
    if (file.is_open()) {
        for (std::string username; std::getline(file, username); ret.insert(std::move(username))) {}
    }
    return ret;
}

void set_bans(const std::set<std::string>& bans) {
    std::ofstream file("bans.txt");
    for (const auto& username : bans) {
        file << username << '\n';
    }
}
