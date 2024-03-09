#include "Polyweb/polyweb.hpp"
#include "adblock.hpp"
#include "pages.hpp"
#include "util.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

void route(pn::SharedSocket<pn::tcp::Connection> a, pn::tcp::BufReceiver& buf_receiver, pn::WeakSocket<pn::tcp::Connection> b) {
    char buf[UINT16_MAX];
    for (;;) {
        long recv_result;
        if ((recv_result = a->recv(buf, UINT16_MAX)) == PN_ERROR) {
            ERR_NET;
            break;
        } else if (recv_result == 0) {
            INFO("Connection closed");
            break;
        }

        if (pn::SharedSocket<pn::tcp::Connection> b_locked = b.lock()) {
            long send_result;
            if ((send_result = b_locked->send(buf, recv_result)) == PN_ERROR) {
                ERR_NET;
                break;
            } else if (send_result != recv_result) {
                break;
            }
        } else {
            break;
        }
    }
}

void init_conn(pn::SharedSocket<pw::Connection> conn, pn::tcp::BufReceiver& conn_buf_receiver) {
    if (set_socket_timeout(*conn, std::chrono::seconds(30)) == PN_ERROR) {
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

    Timer<> timer([](std::chrono::steady_clock::duration duration) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        response_time += std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    });

    stats_mutex.lock();
    ++requests_received;
    decltype(activity)::iterator date_it;
    std::string date = get_date();
    if ((date_it = activity.find(date)) != activity.end()) {
        ++date_it->second;
    } else {
        if (activity.size() >= 180) {
            activity.clear();
        }
        activity[date] = 1;
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
        timer.done();

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
            ERR("Failed to parse URL: " << req.target);
            if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version) == PN_ERROR) {
                ERR_WEB;
            }
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

            if (conn->send(resp, req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }

            return;
        }

        // Prepare request
        req.target = url_info.path;
        req.headers["Accept-Encoding"] = "chunked";
        req.headers.insert(CONNECTION_CLOSE);

        INFO("Routing HTTP request to " << url_info.host);

        pw::HTTPResponse resp;
        if (pw::fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", req, resp, {}, 0) == PN_ERROR) {
            ERR_WEB;
            ERR("Failed to perform HTTP request to " << url_info.host);
            if (conn->send(error_page(500, url_info.host, pw::universal_strerror(), req.http_version)) == PN_ERROR) {
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
            ERR_WEB;
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

    pn::quit();
    return 0;
}
