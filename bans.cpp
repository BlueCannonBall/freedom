#include "bans.hpp"
#include <fstream>
#include <mutex>

std::mutex mutex;

std::set<std::string> get_bans() {
    std::lock_guard<std::mutex> lock(mutex);
    std::set<std::string> ret;
    std::ifstream file("bans.txt");
    if (file.is_open()) {
        for (std::string username; std::getline(file, username); ret.insert(std::move(username))) {}
    }
    return ret;
}

void set_bans(const std::set<std::string>& bans) {
    std::lock_guard<std::mutex> lock(mutex);
    std::ofstream file("bans.txt");
    for (const auto& username : bans) {
        file << username << '\n';
    }
}
