#include "Polyweb/polyweb.hpp"
#include <chrono>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

extern std::mutex stats_mutex;
extern const time_t running_since;
extern unsigned long long requests_received;
extern unsigned long long ads_blocked;
extern std::chrono::milliseconds response_time;
extern std::unordered_map<std::string, unsigned long long> users;
extern std::map<std::string, unsigned long long> activity;

pw::HTTPResponse stats_page(const std::string& http_version = "HTTP/1.1");
pw::HTTPResponse error_page(uint16_t status_code, const std::string& host, const std::string& error_message, const std::string& http_version = "HTTP/1.1");
