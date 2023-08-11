#include "Polyweb/polyweb.hpp"
#include "adblock.hpp"
#include <cctype>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <utility>
#include <vector>

#define CONNECTION_CLOSE \
    { "Connection", "close" }
#define PROXY_CONNECTION_CLOSE \
    { "Proxy-Connection", "close" }
#define PROXY_AUTHENTICATE_BASIC \
    { "Proxy-Authenticate", "basic" }

#define INFO(msg)                                               \
    do {                                                        \
        std::cout << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Info: " << msg << std::endl;              \
    } while (0)
#define ERR(msg)                                                \
    do {                                                        \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Error: " << msg << std::endl;             \
    } while (0)
#define ERR_NET                                                                  \
    do {                                                                         \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] "                  \
                  << "Network error: " << pn::universal_strerror() << std::endl; \
    } while (0)
#define ERR_WEB                                                 \
    do {                                                        \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << pw::universal_strerror() << std::endl;     \
    } while (0)
#define ERR_CLI(msg)                                            \
    do {                                                        \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "CLI error: " << msg << std::endl;         \
    } while (0)

std::string password;

// Stats
std::mutex stats_mtx;
const time_t running_since = time(nullptr);
unsigned long long total_requests_received = 0;
std::unordered_map<std::string, unsigned long long> users;
std::unordered_map<std::string, unsigned long long> sites;

pw::HTTPResponse stats_page() {
    std::lock_guard<std::mutex> lock(stats_mtx);

    std::ostringstream html;
    html << "<html>";
    html << "<head>";
    html << "<title>Proxy Statistics</title>";
    html << "</head>";

    html << "<body>";
    html << "<h1>Proxy Statistics</h1>";

    html << "<p>Running since: " << pw::build_date(running_since) << "</p>";
    html << "<p>Requests received: " << total_requests_received << "</p>";
    html << "<p>Requests per second: " << ((float) total_requests_received / (time(nullptr) - running_since)) << "</p>";

    html << "<p>Unique users: " << users.size() << "</p>";
    html << "<p>Most active users:</p>";
    html << "<ol>";
    std::vector<std::pair<std::string, unsigned long long>> user_pairs(users.begin(), users.end());
    std::sort(user_pairs.begin(), user_pairs.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    for (const auto& user : user_pairs) {
        html << "<li>" << user.first << " - " << user.second << " request(s)</li>";
    }
    html << "</ol>";

    html << "<p>Most used sites:</p>";
    html << "<ol>";
    std::vector<std::pair<std::string, unsigned long long>> site_pairs(sites.begin(), sites.end());
    std::sort(site_pairs.begin(), site_pairs.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    for (const auto& site : site_pairs) {
        html << "<li>" << site.first << " - " << site.second << " visit(s)</li>";
    }
    html << "</ol>";
    html << "</body>";
    html << "</html>";

    return pw::HTTPResponse("200", html.str(), {{"Host", "http://proxy.info"}, {"Content-Type", "text/html"}, CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE});
}

int configure_socket(pn::Socket& s) {
    const int value = 1;
    if (s.setsockopt(IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#ifdef __linux__
    if (s.setsockopt(IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
#endif
    if (s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(int)) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

int set_socket_timeout(pn::Socket& s, struct timeval timeout) {
    if (s.setsockopt(SOL_SOCKET, SO_RCVTIMEO, (const char*) &timeout, sizeof(struct timeval)) == PN_ERROR) {
        return PN_ERROR;
    }
    if (s.setsockopt(SOL_SOCKET, SO_SNDTIMEO, (const char*) &timeout, sizeof(struct timeval)) == PN_ERROR) {
        return PN_ERROR;
    }
    return PN_OK;
}

void route(pn::SharedSock<pn::tcp::Connection> a, pn::tcp::BufReceiver& buf_receiver, pn::WeakSock<pn::tcp::Connection> b) {
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

        pn::SharedSock<pn::tcp::Connection> b_locked;
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

void init_conn(pn::SharedSock<pw::Connection> conn, pn::tcp::BufReceiver& conn_buf_receiver) {
    if (set_socket_timeout(*conn, (struct timeval) {60, 0}) == PN_ERROR) {
        ERR_NET;
        ERR("Failed to configure socket");
        conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}));
        return;
    }

    pw::HTTPRequest req;
    if (req.parse(*conn, conn_buf_receiver) == PN_ERROR) {
        ERR_WEB;
        ERR("Failed to parse HTTP request");
        std::string resp_status_code;
        switch (pw::get_last_error()) {
            case PW_ENET: {
                resp_status_code = "500";
                break;
            }

            case PW_EWEB: {
                resp_status_code = "400";
                break;
            }
        }
        conn->send(pw::HTTPResponse::make_basic(resp_status_code, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}));
        return;
    }

    stats_mtx.lock();
    ++total_requests_received;
    stats_mtx.unlock();

    if (!password.empty()) {
        if (!req.headers.count("Proxy-Authorization")) {
            ERR("Authentication not provided");
            if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        } else {
            std::vector<std::string> split_auth;
            boost::split(split_auth, req.headers["Proxy-Authorization"], isspace);
            if (split_auth.size() < 2) {
                ERR("Authorization failed: Bad Proxy-Authorization header");
                if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                    ERR_WEB;
                return;
            } else if (boost::to_lower_copy(split_auth[0]) != "basic") {
                ERR("Authorization failed: Unsupported authentication scheme");
                if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                    ERR_WEB;
                return;
            } else {
                auto decoded_auth = pw::b64_decode(split_auth[1]);
                std::string decoded_auth_string(decoded_auth.begin(), decoded_auth.end());

                std::vector<std::string> split_decoded_auth;
                boost::split(split_decoded_auth, decoded_auth_string, boost::is_any_of(":"));
                if (split_decoded_auth.size() != 2) {
                    ERR("Authorization failed: Bad username:password combination");
                    if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PN_ERROR)
                        ERR_WEB;
                    return;
                } else if (split_decoded_auth[1] != password) {
                    ERR("Authorization failed: Incorrect password");
                    if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PN_ERROR)
                        ERR_WEB;
                    return;
                }

                stats_mtx.lock();
                decltype(users)::iterator user_it;
                if ((user_it = users.find(split_decoded_auth[0])) != users.end()) {
                    ++user_it->second;
                } else {
                    users[split_decoded_auth[0]] = 1;
                }
                stats_mtx.unlock();

                INFO("User " << std::quoted(split_decoded_auth[0]) << " successfully authorized");
            }
        }
    }

    if (req.method == "CONNECT") {
        if (boost::starts_with(req.target, "http://") ||
            boost::starts_with(req.target, "https://") ||
            boost::starts_with(req.target, "ws://") ||
            boost::starts_with(req.target, "wss://")) {
            ERR("Client attempted use absolute-form target in HTTP CONNECT request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        if (set_socket_timeout(*conn, (struct timeval) {7200, 0}) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE})) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        std::vector<std::string> split_host;
        boost::split(split_host, req.target, boost::is_any_of(":"));

        if (split_host.size() > 2) {
            ERR("Failed to parse target of HTTP CONNECT request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        } else if (split_host.size() == 1) {
            split_host.push_back("80");
        }

        if (adblock::check_hostname(split_host[0])) {
            INFO("Got ad connection");
            if (conn->send(pw::HTTPResponse::make_basic("403", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        stats_mtx.lock();
        if (sites.size() >= 4096) {
            sites.clear();
        }
        decltype(sites)::iterator site_it;
        if ((site_it = sites.find(split_host[0])) != sites.end()) {
            ++site_it->second;
        } else {
            sites[split_host[0]] = 1;
        }
        stats_mtx.unlock();

        pn::SharedSock<pn::tcp::Client> proxy;
        pn::tcp::BufReceiver proxy_buf_receiver;
        if (proxy->connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        if (configure_socket(*proxy) == PN_ERROR || set_socket_timeout(*proxy, (struct timeval) {7200, 0}) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        if (conn->send(pw::HTTPResponse("200", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE})) == PN_ERROR) {
            ERR_WEB;
            return;
        }

        INFO("Routing connection to " << split_host[0] << ':' << split_host[1]);
        pw::threadpool.schedule([conn, conn_buf_receiver, proxy](void*) mutable {
            route(std::move(conn), conn_buf_receiver, std::move(proxy));
        });
        route(std::move(proxy), proxy_buf_receiver, std::move(conn));
    } else {
        size_t protocol_len;
        if (boost::starts_with(req.target, "http://")) {
            protocol_len = 7;
        } else {
            ERR("Client (possibly) attempted to make normal HTTP request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        pw::HTTPHeaders::const_iterator connection_it;
        pw::HTTPHeaders::const_iterator upgrade_it;
        if (req.http_version == "HTTP/1.1" &&
            req.method == "GET" &&
            (upgrade_it = req.headers.find("Upgrade")) != req.headers.end() &&
            (connection_it = req.headers.find("Connection")) != req.headers.end() &&
            boost::contains(boost::to_lower_copy(upgrade_it->second), "websocket") &&
            boost::to_lower_copy(connection_it->second) == "upgrade") {
            ERR("Client attempted to make absolute-target WebSocket connection");
            if (conn->send(pw::HTTPResponse::make_basic("501", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        std::string::iterator path_begin;
        std::string host(req.target.begin() + protocol_len, path_begin = std::find(req.target.begin() + protocol_len + 1, req.target.end(), '/'));
        req.target = std::string(path_begin, req.target.end());
        std::vector<std::string> split_host;
        boost::split(split_host, host, boost::is_any_of(":"));

        if (split_host.size() > 2) {
            ERR("Failed to parse host of absolute-form target HTTP request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        } else if (split_host.size() == 1) {
            split_host.push_back("80");
        }

        if (adblock::check_hostname(split_host[0])) {
            INFO("Got ad connection");
            if (conn->send(pw::HTTPResponse::make_basic("403", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        stats_mtx.lock();
        if (sites.size() >= 4096) {
            sites.clear();
        }
        decltype(sites)::iterator site_it;
        if ((site_it = sites.find(split_host[0])) != sites.end()) {
            ++site_it->second;
        } else {
            sites[split_host[0]] = 1;
        }
        stats_mtx.unlock();

        if (split_host[0] == "proxy.info") {
            pw::HTTPResponse resp;
            if (req.target == "/") {
                resp = stats_page();
            } else {
                resp = pw::HTTPResponse::make_basic("404", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
            }
            std::vector<char> proxied_resp_data = resp.build();
            if (conn->send(proxied_resp_data.data(), proxied_resp_data.size()) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        pn::UniqueSock<pn::tcp::Client> proxy;
        pn::tcp::BufReceiver proxy_buf_receiver;
        if (proxy->connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        if (configure_socket(*proxy) == PN_ERROR || set_socket_timeout(*proxy, (struct timeval) {30, 0}) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        for (auto it = req.headers.cbegin(); it != req.headers.cend();) {
            if (boost::starts_with(boost::to_lower_copy(it->first), "proxy-")) {
                it = req.headers.erase(it);
            } else {
                ++it;
            }
        }

        req.headers["Host"] = std::move(host);
        req.headers["Accept-Encoding"] = "chunked";
        req.headers.insert(CONNECTION_CLOSE);

        INFO("Routing HTTP request to " << split_host[0] << ':' << split_host[1]);

        std::vector<char> proxied_req_data = req.build();
        if (proxy->send(proxied_req_data.data(), proxied_req_data.size()) == PN_ERROR) {
            ERR_NET;
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        pw::HTTPResponse resp;
        if (resp.parse(*proxy, proxy_buf_receiver) == PN_ERROR) {
            ERR_WEB;
            ERR("Failed to parse HTTP response");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PN_ERROR)
                ERR_WEB;
            return;
        }

        resp.headers.insert(PROXY_CONNECTION_CLOSE);
        pw::HTTPHeaders::const_iterator transfer_encoding_it;
        if ((transfer_encoding_it = resp.headers.find("Transfer-Encoding")) != resp.headers.end()) {
            resp.headers.erase(transfer_encoding_it);
        }

        std::vector<char> proxied_resp_data = resp.build();
        if (conn->send(proxied_resp_data.data(), proxied_resp_data.size()) == PN_ERROR) {
            ERR_NET;
            return;
        }
    }
}

int main(int argc, char** argv) {
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

    pn::UniqueSock<pn::tcp::Server> server;
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
                init_conn(pn::SharedSock<pw::Connection>(conn), buf_receiver);
            });
            return true;
        }) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    adblock::quit();
    pn::quit();
    return 0;
}
