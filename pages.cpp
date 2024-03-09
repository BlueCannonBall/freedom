#include "pages.hpp"
#include "Polyweb/polyweb.hpp"
#include "util.hpp"
#include <algorithm>
#include <iomanip>
#include <locale>
#include <sstream>

std::mutex stats_mutex;
const time_t running_since = time(nullptr);
unsigned long long requests_received = 0;
unsigned long long ads_blocked = 0;
std::chrono::milliseconds response_time = std::chrono::milliseconds::zero();
std::unordered_map<std::string, unsigned long long> users;
std::map<std::string, unsigned long long> activity;

class CommaNumpunct : public std::numpunct<char> {
protected:
    char do_thousands_sep() const override {
        return ',';
    }

    std::string do_grouping() const override {
        return "\03";
    }
};

pw::HTTPResponse stats_page(const std::string& http_version) {
    std::lock_guard<std::mutex> lock(stats_mutex);
    std::ostringstream html;
    html.imbue(std::locale(std::locale("C"), new CommaNumpunct));
    html << std::fixed << std::setprecision(3);
    html << "<html>";
    html << "<head>";
    html << "<title>Proxy Statistics</title>";
    html << "<style>html { margin: 0; padding: 0; } body { margin: 0; padding: 10px; font-family: sans-serif; color: rgb(204, 204, 204); background-color: rgb(17, 17, 17); } h1, h2, h3, h4, h5, h6 { color: #FFFFFF; } a { color: #4287F5; }</style>";
    html << "</head>";

    html << "<body style=\"display: flex; flex-direction: column; box-sizing: border-box; height: 100%;\">";
    html << "<h1 style=\"margin: 5px; text-align: center;\">Proxy Statistics</h1>";

    html << "<div style=\"display: flex; flex: 1; min-height: 0;\">";
    html << "<div style=\"flex: 1; min-width: 0; margin: 10px; overflow-y: auto;\"/>";
    html << "<p><strong>Running since:</strong> " << pw::build_date(running_since) << "</p>";
    html << "<p><strong>Requests received:</strong> " << requests_received << "</p>";
    html << "<p><strong>Ads blocked:</strong> " << ads_blocked << "</p>";
    html << "<p><strong>Average response time:</strong> " << (float) response_time.count() / requests_received << "ms</p>";
    html << "<p><strong>Requests per second:</strong> " << (float) requests_received / (time(nullptr) - running_since) << "</p>";

    if (!users.empty()) {
        html << "<p><strong>Unique users:</strong> " << users.size() << "</p>";
        html << "<p><strong>Most active users:</strong></p>";
        html << "<ol>";
        std::vector<std::pair<std::string, unsigned long long>> user_pairs(users.begin(), users.end());
        std::sort(user_pairs.begin(), user_pairs.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });
        for (const auto& user : user_pairs) {
            html << "<li>" << pw::escape_xml(user.first) << " - " << user.second << " request(s)</li>";
        }
        html << "</ol>";

        html << "<p><a href=\"#\" role=\"button\" onclick=\"changeUsername(); return false;\">Change Username</a></p>";
    }
    html << "</div>";

    html << "<div style=\"flex: 1; min-width: 0; margin: 10px; padding: 10px; background-color: rgb(34, 34, 34); border-radius: 10px;\"><canvas id=\"chart\"></canvas></div>";
    html << "</div>";

    html << "<div style=\"display: flex;\">";
    html << "<h2 style=\"margin: 5px; text-align: left; flex: 1; color: #FF4545;\">By Charter of His Majesty The King</h2>";
    html << "<h2 style=\"margin: 5px; text-align: right; flex: 1; color: #FF4545;\">Royal Society of Burlington &#9876;</h2>";
    html << "</div>";

    html << "<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>";
    html << "<script>";
    html << "const labels = [";
    for (const auto& date : activity) {
        html << std::quoted(date.first) << ',';
    }
    html << "];";
    html << "const data = [";
    for (const auto& date : activity) {
        html << std::to_string(date.second) << ',';
    }
    html << "];";
    html << R"delimiter(
        const ctx = document.getElementById("chart");

        Chart.defaults.color = "rgb(204, 204, 204)";
        new Chart(ctx, {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "# of Requests",
                    backgroundColor: "#FF4545",
                    data,
                    borderWidth: 1,
                }],
            },
            options: {
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: {
                            color: "rgb(85, 85, 85)",
                        },
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: "rgb(85, 85, 85)",
                        },
                    },
                },
            },
        });

        function changeUsername() {
            fetch("http://proxy.info/change_username");
        }
    )delimiter";
    html << "</script>";

    html << "</body>";
    html << "</html>";
    return pw::HTTPResponse(200, html.str(), {{"Content-Type", "text/html"}, CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, http_version);
}

pw::HTTPResponse error_page(uint16_t status_code, const std::string& host, const std::string& error_message, const std::string& http_version) {
    std::ostringstream html;
    html << "<html>";
    html << "<head>";
    html << "<title>" << host << "</title>";
    html << "<style>html { margin: 0; padding: 0; } body { margin: 0; padding: 10px; font-family: sans-serif; color: rgb(204, 204, 204); background-color: rgb(17, 17, 17); } h1, h2, h3, h4, h5, h6 { color: #FFFFFF; } a { color: #4287F5; }</style>";
    html << "</head>";

    html << "<body>";

    html << "<div style=\"margin: 0; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);\">";
    html << "<h1 style=\"text-align: center;\">\"" << host << "\" could not be loaded</h1>";
    html << "<p style=\"text-align: center;\"><strong>Error:</strong> " << error_message << "</p>";
    html << "</div>";

    html << "</body>";
    html << "</html>";
    return pw::HTTPResponse(status_code, html.str(), {{"Content-Type", "text/html"}, CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, http_version);
}
