#include "Polyweb/polyweb.hpp"
#include "adblock.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#ifndef _WIN32
    #include <sys/time.h>
#endif

#define CONNECTION_CLOSE \
    { "Connection", "close" }
#define PROXY_CONNECTION_CLOSE \
    { "Proxy-Connection", "close" }
#define PROXY_AUTHENTICATE_BASIC \
    { "Proxy-Authenticate", "basic" }

#define INFO(message)                                           \
    {                                                           \
        std::cout << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Info: " << message << std::endl;          \
    }
#define ERR(message)                                            \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Error: " << message << std::endl;         \
    }
#define ERR_NET                                                                  \
    {                                                                            \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] "                  \
                  << "Network error: " << pn::universal_strerror() << std::endl; \
    }
#define ERR_WEB                                                 \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << pw::universal_strerror() << std::endl;     \
    }
#define ERR_CLI(message)                                        \
    {                                                           \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "CLI error: " << message << std::endl;     \
    }

std::string password;

// Stats
std::mutex stats_mutex;
const time_t running_since = time(nullptr);
unsigned long long total_requests_received = 0;
unsigned long long ads_blocked = 0;
std::unordered_map<std::string, unsigned long long> users;
std::map<std::string, unsigned long long> activity;

pw::HTTPResponse stats_page(const std::string& http_version = "HTTP/1.1") {
    std::lock_guard<std::mutex> lock(stats_mutex);
    std::ostringstream html;
    html.imbue(std::locale("en_US.UTF-8"));
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
    html << "<p><strong>Requests received:</strong> " << total_requests_received << "</p>";
    html << "<p><strong>Ads blocked:</strong> " << ads_blocked << "</p>";
    html << "<p><strong>Requests per second:</strong> " << (float) total_requests_received / (time(nullptr) - running_since) << "</p>";

    if (!password.empty()) {
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
    for (const auto& day : activity) {
        html << std::quoted(day.first) << ',';
    }
    html << "];";
    html << "const data = [";
    for (const auto& day : activity) {
        html << std::to_string(day.second) << ',';
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

pw::HTTPResponse error_page(uint16_t status_code, const std::string& host, const std::string& error_message, const std::string& http_version = "HTTP/1.1") {
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

int configure_socket(pn::Socket& socket) {
    static constexpr int value = 1;
    if (socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#ifdef __linux__
    if (socket.setsockopt(IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#endif
    if (socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

int set_socket_timeout(pn::Socket& socket, std::chrono::milliseconds timeout_duration) {
#ifdef _WIN32
    DWORD timeout = timeout_duration.count();
#else
    struct timeval timeout;
    timeout.tv_sec = timeout_duration.count() / 1000;
    timeout.tv_usec = (timeout_duration.count() % 1000) * 1000;
#endif
    if (socket.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) == PN_ERROR) {
        return PN_ERROR;
    }
    if (socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

void route(pn::SharedSocket<pn::tcp::Connection> a, pn::tcp::BufReceiver& buf_receiver, pn::WeakSocket<pn::tcp::Connection> b) {
    char buf[UINT16_MAX];
    for (;;) {
        ssize_t read_result;
        if ((read_result = a->recv(buf, UINT16_MAX)) == PN_ERROR) {
            ERR_NET;
            break;
        } else if (read_result == 0) {
            INFO("Connection closed");
            break;
        }

        pn::SharedSocket<pn::tcp::Connection> b_locked;
        if ((b_locked = b.lock())) {
            if (b_locked->send(buf, read_result) == PN_ERROR) {
                ERR_NET;
                break;
            }
        } else {
            break;
        }
    }
}

void init_conn(pn::SharedSocket<pw::Connection> conn, pn::tcp::BufReceiver& conn_buf_receiver) {
    if (set_socket_timeout(*conn, std::chrono::seconds(60)) == PN_ERROR) {
        ERR_NET;
        ERR("Failed to configure socket");
        conn->send_basic(500, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE});
        return;
    }

    pw::HTTPRequest req;
    if (req.parse(*conn, conn_buf_receiver) == PN_ERROR) {
        ERR_WEB;
        ERR("Failed to parse HTTP request");
        uint16_t resp_status_code;
        switch (pw::get_last_error()) {
        case PW_ENET:
            resp_status_code = 500;
            break;

        case PW_EWEB:
            resp_status_code = 400;
            break;

        default:
            throw std::logic_error("Invalid error");
        }
        conn->send_basic(resp_status_code, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE});
        return;
    }

    stats_mutex.lock();
    ++total_requests_received;
#ifdef _WIN32
    struct tm timeinfo = *localtime(&rawtime);
#else
    time_t rawtime = time(nullptr);
    struct tm timeinfo;
    localtime_r(&rawtime, &timeinfo);
#endif
    std::ostringstream ss;
    ss.imbue(std::locale("C"));
    ss << std::put_time(&timeinfo, "%m/%d/%y");
    decltype(activity)::iterator day_it;
    if ((day_it = activity.find(ss.str())) != activity.end()) {
        ++day_it->second;
    } else {
        if (activity.size() >= 180) {
            activity.clear();
        }
        activity[ss.str()] = 1;
    }
    stats_mutex.unlock();

    if (!password.empty()) {
        if (!req.headers.count("Proxy-Authorization")) {
            ERR("Authentication not provided");
            if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        } else {
            std::vector<std::string> split_auth = pw::string::split_and_trim(req.headers["Proxy-Authorization"], ' ');
            if (split_auth.size() < 2) {
                ERR("Authorization failed: Bad Proxy-Authorization header");
                if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                    ERR_WEB;
                }
                return;
            } else if (pw::string::to_lower_copy(split_auth[0]) != "basic") {
                ERR("Authorization failed: Unsupported authentication scheme");
                if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                    ERR_WEB;
                }
                return;
            } else {
                auto decoded_auth = pw::base64_decode(split_auth[1]);
                std::string decoded_auth_string(decoded_auth.begin(), decoded_auth.end());

                std::vector<std::string> split_decoded_auth = pw::string::split(decoded_auth_string, ':');
                if (split_decoded_auth.size() != 2) {
                    ERR("Authorization failed: Bad username:password combination");
                    if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version) == PN_ERROR) {
                        ERR_WEB;
                    }
                    return;
                } else if (split_decoded_auth[1] != password) {
                    ERR("Authorization failed: Incorrect password");
                    if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version) == PN_ERROR) {
                        ERR_WEB;
                    }
                    return;
                }

                stats_mutex.lock();
                decltype(users)::iterator user_it;
                if ((user_it = users.find(split_decoded_auth[0])) != users.end()) {
                    ++user_it->second;
                } else {
                    if (users.size() >= 1024) {
                        users.clear();
                    }
                    users[split_decoded_auth[0]] = 1;
                }
                stats_mutex.unlock();

                INFO("User " << std::quoted(split_decoded_auth[0]) << " successfully authorized");
            }
        }
    }

    if (req.method == "CONNECT") {
        if (pw::string::starts_with(req.target, "http://") ||
            pw::string::starts_with(req.target, "https://") ||
            pw::string::starts_with(req.target, "ws://") ||
            pw::string::starts_with(req.target, "wss://")) {
            ERR("Client attempted use absolute-form target in HTTP CONNECT request");
            if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (set_socket_timeout(*conn, std::chrono::hours(2)) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send_basic(500, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        std::vector<std::string> split_host = pw::string::split(req.target, ':');

        if (split_host.empty() || split_host.size() > 2) {
            ERR("Failed to parse target of HTTP CONNECT request");
            if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        } else if (split_host.size() == 1) {
            split_host.push_back("80");
        }

        if (adblock::check_hostname(split_host[0])) {
            INFO("Got ad connection");
            stats_mutex.lock();
            ++ads_blocked;
            stats_mutex.unlock();
            if (conn->send(error_page(403, req.target, "Ad detected", req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        pn::SharedSocket<pn::tcp::Client> proxy;
        pn::tcp::BufReceiver proxy_buf_receiver;
        if (proxy->connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(error_page(404, req.target, pn::universal_strerror(), req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (configure_socket(*proxy) == PN_ERROR || set_socket_timeout(*proxy, std::chrono::hours(2)) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(error_page(500, req.target, pn::universal_strerror(), req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (conn->send(pw::HTTPResponse(200, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE})) == PN_ERROR) {
            ERR_WEB;
            return;
        }

        INFO("Routing connection to " << split_host[0] << ':' << split_host[1]);
        pw::threadpool.schedule([conn, conn_buf_receiver, proxy](void*) mutable {
            route(std::move(conn), conn_buf_receiver, std::move(proxy));
        },
            nullptr,
            true);
        route(std::move(proxy), proxy_buf_receiver, std::move(conn));
    } else {
        if (req.target == "/stats") {
            if (conn->send(stats_page(req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        pw::URLInfo url_info;
        if (url_info.parse(req.target) == PN_ERROR) {
            ERR_WEB;
            ERR("Failed to parse URL");
            return;
        }

        pw::HTTPHeaders::const_iterator connection_it;
        if (req.method == "GET" &&
            req.http_version == "HTTP/1.1" &&
            (connection_it = req.headers.find("Connection")) != req.headers.end() &&
            pw::string::to_lower_copy(connection_it->second) == "upgrade") {
            ERR("Client attempted to upgrade with an absolute-target request");
            if (conn->send_basic(501, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (adblock::check_hostname(url_info.hostname())) {
            INFO("Got ad connection");
            stats_mutex.lock();
            ++ads_blocked;
            stats_mutex.unlock();
            if (conn->send(error_page(403, url_info.host, "Ad detected", req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (url_info.hostname() == "proxy.info") {
            pw::HTTPResponse resp;
            if (url_info.path == "/") {
                resp = stats_page(req.http_version);
            } else if (url_info.path == "/change_username") {
                if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version) == PN_ERROR) {
                    ERR_WEB;
                }
                return;
            } else {
                resp = error_page(404, url_info.host, req.target + " could not be found", req.http_version);
            }

            if (conn->send(resp) == PN_ERROR) {
                ERR_NET;
            }

            return;
        }

        req.headers["Accept-Encoding"] = "chunked";
        req.headers.insert(CONNECTION_CLOSE);

        INFO("Routing HTTP request to " << url_info.host);

        pw::HTTPResponse resp;
        if (pw::fetch(req.method, req.target, resp, std::move(req.body), std::move(req.headers), {}, 3, req.http_version) == PN_ERROR) {
            if (conn->send(error_page(400, url_info.host, pw::universal_strerror(), req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        resp.headers.insert(PROXY_CONNECTION_CLOSE);
        pw::HTTPHeaders::const_iterator transfer_encoding_it;
        if ((transfer_encoding_it = resp.headers.find("Transfer-Encoding")) != resp.headers.end()) {
            resp.headers.erase(transfer_encoding_it);
        }

        if (conn->send(resp) == PN_ERROR) {
            ERR_NET;
            return;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        ERR_CLI("Missing arguments");
        std::cout << "Usage: " << argv[0] << " <PORT> [PASSWORD]\n";
        return 1;
    }

    if (argc >= 3) {
        password = argv[2];
    }

    std::cout << "Cross-platform networking brought to you by:\n";
    pn::init(true);
    adblock::init();

    pn::UniqueSocket<pn::tcp::Server> server;
    if (server->bind("0.0.0.0", argv[1]) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    if (configure_socket(*server) == PN_ERROR) {
        ERR_NET;
        ERR("Failed to configure server socket");
        return 1;
    }

    INFO("Proxy server listening on port " << argv[1]);
    if (server->listen([](pn::tcp::Connection& conn, void*) -> bool {
            pw::threadpool.schedule([conn](void* data) {
                pn::tcp::BufReceiver buf_receiver;
                init_conn(pn::SharedSocket<pw::Connection>(conn), buf_receiver);
            },
                nullptr,
                true);
            return true;
        }) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    adblock::quit();
    pn::quit();
    return 0;
}
