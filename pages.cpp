#include "pages.hpp"
#include "Polyweb/polyweb.hpp"
#include "bans.hpp"
#include "util.hpp"
#include <algorithm>
#include <iomanip>
#include <locale>
#include <sstream>

namespace pages {
    std::mutex stats_mutex;
    const time_t running_since = time(nullptr);
    unsigned long long requests_handled = 0;
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

    pw::HTTPResponse stats_page(pn::StringView http_version) {
        std::lock_guard<std::mutex> lock(stats_mutex);

        std::vector<std::pair<std::string, unsigned long long>> user_pairs(users.begin(), users.end());
        std::sort(user_pairs.begin(), user_pairs.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

        std::ostringstream html;
        html.imbue(std::locale(std::locale("C"), new CommaNumpunct));
        html << std::fixed << std::setprecision(3);
        html << "<html>";
        html << "<head>";
        html << "<title>Proxy Statistics</title>";
        html << "<style>html { margin: 0; padding: 0; } body { margin: 0; padding: 10px; font-family: sans-serif; color: rgb(204, 204, 204); background-color: rgb(17, 17, 17); } h1, h2, h3, h4, h5, h6 { color: #FFFFFF; } p, ol, ul { margin: 0.75em 0; } a { color: #4287F5; }</style>";
        html << "</head>";

        html << "<body style=\"display: flex; flex-direction: column; box-sizing: border-box; height: 100%;\">";
        html << "<h1 style=\"margin: 5px; text-align: center;\">Proxy Statistics</h1>";

        html << "<div style=\"display: flex; flex: 1; min-height: 0;\">";
        html << "<div style=\"flex: 1; min-width: 0; margin: 10px; overflow-y: auto;\"/>";
        html << "<p><strong>Running since:</strong> " << pw::build_date(running_since) << "</p>";
        html << "<p><strong>Requests handled:</strong> " << requests_handled << "</p>";
        html << "<p><strong>Ads blocked:</strong> " << ads_blocked << "</p>";
        html << "<p><strong>Requests per second:</strong> " << (float) requests_handled / (time(nullptr) - running_since) << "</p>";
        html << "<p><strong>Average response time:</strong> " << (float) response_time.count() / requests_handled << "ms</p>";

        if (!user_pairs.empty()) {
            html << "<p><strong># of users:</strong> " << user_pairs.size() << "</p>";
            html << "<p><strong>Most active users:</strong></p>";
            html << "<ol>";
            for (size_t i = 0; i < user_pairs.size(); ++i) {
                html << "<li>" << pw::xml_escape(user_pairs[i].first) << " - " << user_pairs[i].second << (user_pairs[i].second == 1 ? " request" : " requests");

                html << " (";
                if (bans::is_banned(user_pairs[i].first)) {
                    html << "<a href=\"#\" role=\"button\" onclick=\"unban(usernames[" << i << "]); return false;\">unban</a>";
                } else {
                    html << "<a href=\"#\" role=\"button\" onclick=\"ban(usernames[" << i << "]); return false;\">ban</a>";
                }
                html << ", <a href=\"#\" role=\"button\" onclick=\"deauthenticate(usernames[" << i << "]); return false;\">deauthenticate</a>";
                html << ')';

                html << "</li>";
            }
            html << "</ol>";

            auto bans = bans::get_all_bans();
            html << "<p><strong># of banned users:</strong> " << bans.size() << "</p>";
            if (!bans.empty()) {
                html << "<p><strong>Banned users:</strong></p>";
                html << "<ul>";
                for (const auto& username : bans) {
                    html << "<li>" << pw::xml_escape(username) << " (<a href=\"#\" role=\"button\" onclick=\"unban(" << std::quoted(pw::xml_escape(username), '\'') << "); return false;\">unban</a>)</li>";
                }
                html << "</ul>";
            }

            html << "<p><a href=\"#\" role=\"button\" onclick=\"changeUsername(); return false;\">Change Username</a></p>";
            html << "<p><a href=\"#\" role=\"button\" onclick=\"ban(prompt('Enter a username to ban')); return false;\">Ban Another User</a></p>";
            html << "<p><a href=\"#\" role=\"button\" onclick=\"deauthenticate(prompt('Enter a username to deauthenticate')); return false;\">Deauthenticate Another User</a></p>";
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
        html << "const usernames = [";
        for (const auto& user : user_pairs) {
            html << std::quoted(user.first) << ',';
        }
        html << "];";

        html << "const chartLabels = [";
        for (const auto& date : activity) {
            html << std::quoted(date.first) << ',';
        }
        html << "];";
        html << "const chartData = [";
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
                    labels: chartLabels,
                    datasets: [{
                        label: "# of Requests",
                        backgroundColor: "#FF4545",
                        data: chartData,
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
                fetch("http://stats.gov/change_username");
            }

            function ban(username) {
                if (username !== null) {
                    fetch("http://stats.gov/ban?" +  new URLSearchParams({username}), {
                        method: "PUT",
                    }).then(resp => window.location.reload());
                }
            }

            function unban(username) {
                if (username !== null) {
                    fetch("http://stats.gov/unban?" +  new URLSearchParams({username}), {
                        method: "DELETE",
                    }).then(resp => window.location.reload());
                }
            }

            function deauthenticate(username) {
                if (username !== null) {
                    fetch("http://stats.gov/deauthenticate?" +  new URLSearchParams({username}), {
                        method: "PUT",
                    });
                }
            }
        )delimiter";
        html << "</script>";
        html << "</body>";

        html << "</html>";
        return pw::HTTPResponse(200, html.str(), {{"Content-Type", "text/html"}, CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, http_version);
    }

    pw::HTTPResponse error_page(uint16_t status_code, pn::StringView host, pn::StringView error_message, pn::StringView http_version) {
        std::ostringstream html;
        html << "<html>";
        html << "<head>";
        html << "<title>" << host << "</title>";
        html << "<style>html { margin: 0; padding: 0; } body { margin: 0; padding: 10px; font-family: sans-serif; color: rgb(204, 204, 204); background-color: rgb(17, 17, 17); } h1, h2, h3, h4, h5, h6 { color: #FFFFFF; } p, ol, ul { margin: 0.75em 0; } a { color: #4287F5; }</style>";
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
} // namespace pages
