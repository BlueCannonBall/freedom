#include "Polyweb/polyweb.hpp"
#include <cctype>
#include <iomanip>
#include <mutex>
#include <string>
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
        print_lock.lock();                                      \
        std::cout << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Info: " << msg << std::endl;              \
        print_lock.unlock();                                    \
    } while (0)
#define ERR(msg)                                                \
    do {                                                        \
        print_lock.lock();                                      \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "Error: " << msg << std::endl;             \
        print_lock.unlock();                                    \
    } while (0)
#define ERR_NET                                                                  \
    do {                                                                         \
        print_lock.lock();                                                       \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] "                  \
                  << "Network error: " << pn::universal_strerror() << std::endl; \
        print_lock.unlock();                                                     \
    } while (0)
#define ERR_WEB                                                 \
    do {                                                        \
        print_lock.lock();                                      \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << pw::universal_strerror() << std::endl;     \
        print_lock.unlock();                                    \
    } while (0)
#define ERR_CLI(msg)                                            \
    do {                                                        \
        print_lock.lock();                                      \
        std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
                  << "CLI error: " << msg << std::endl;         \
        print_lock.unlock();                                    \
    } while (0)

std::mutex print_lock;
std::string password;

int configure_socket(pn::Socket& s) {
    const int value = 1;
    if (s.setsockopt(IPPROTO_TCP, TCP_NODELAY, (const char*) &value, sizeof(int)) == PW_ERROR) {
        ERR_NET;
        return PW_ERROR;
    }
#ifdef __linux__
    if (s.setsockopt(IPPROTO_TCP, TCP_QUICKACK, (const char*) &value, sizeof(int)) == PW_ERROR) {
        ERR_NET;
        return PW_ERROR;
    }
#endif
    if (s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, (const char*) &value, sizeof(int)) == PW_ERROR) {
        ERR_NET;
        return PW_ERROR;
    }

    return PW_OK;
}

void route(pn::SharedSock<pn::tcp::Connection> a, pn::WeakSock<pn::tcp::Connection> b) {
    char buf[UINT16_MAX];
    for (;;) {
        ssize_t read_result;
        if ((read_result = a->recv(buf, sizeof(buf))) == 0) {
            INFO("Connection closed");
            break;
        } else if (read_result == PW_ERROR) {
            ERR_NET;
            break;
        }

        pn::SharedSock<pn::tcp::Connection> b_locked;
        if ((b_locked = b.lock())) {
            if (b_locked->send(buf, read_result) == PW_ERROR) {
                ERR_NET;
                break;
            }
        } else {
            break;
        }
    }
}

void init_conn(pn::SharedSock<pw::Connection> conn) {
    pw::HTTPRequest req;
    if (req.parse(*conn) == PW_ERROR) {
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

    if (!password.empty()) {
        if (!req.headers.count("Proxy-Authorization")) {
            ERR("Authentication not provided");
            if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        } else {
            std::vector<std::string> split_auth;
            boost::split(split_auth, req.headers["Proxy-Authorization"], isspace);
            if (split_auth.size() < 2) {
                ERR("Authorization failed: Bad Proxy-Authorization header");
                if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                    ERR_WEB;
                return;
            } else if (boost::to_lower_copy(split_auth[0]) != "basic") {
                ERR("Authorization failed: Unsupported authentication scheme");
                if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                    ERR_WEB;
                return;
            } else {
                auto decoded_auth = pw::b64_decode(split_auth[1]);
                std::string decoded_auth_string(decoded_auth.begin(), decoded_auth.end());

                std::vector<std::string> split_decoded_auth;
                boost::split(split_decoded_auth, decoded_auth_string, boost::is_any_of(":"));
                if (split_decoded_auth.size() != 2) {
                    ERR("Authorization failed: Bad username:password combination");
                    if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PW_ERROR)
                        ERR_WEB;
                    return;
                } else if (split_decoded_auth[1] != password) {
                    ERR("Authorization failed: Incorrect password");
                    if (conn->send(pw::HTTPResponse::make_basic("407", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version)) == PW_ERROR)
                        ERR_WEB;
                    return;
                }

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
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        std::vector<std::string> split_target;
        boost::split(split_target, req.target, boost::is_any_of(":"));

        if (split_target.size() > 2) {
            ERR("Failed to parse target of HTTP CONNECT request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        } else if (split_target.size() == 1) {
            split_target.push_back("80");
        }

        pn::SharedSock<pn::tcp::Client> proxy;
        if (proxy->connect(split_target[0], split_target[1]) == PW_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        if (configure_socket(*proxy) == PW_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        if (conn->send(pw::HTTPResponse("200", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE})) == PW_ERROR) {
            ERR_WEB;
            return;
        }

        INFO("Routing connection to " << split_target[0] << ':' << split_target[1]);
        pw::threadpool.schedule([conn, proxy](void*) mutable {
            route(std::move(conn), std::move(proxy));
        });
        route(std::move(proxy), std::move(conn));
    } else {
        size_t protocol_len;
        if (boost::starts_with(req.target, "http://")) {
            protocol_len = 7;
        } else {
            ERR("Client (possibly) attempted to make normal HTTP request");
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        if (req.http_version == "HTTP/1.1" &&
            req.method == "GET" &&
            req.headers.count("Upgrade") &&
            req.headers.count("Connection") &&
            boost::to_lower_copy(req.headers["Connection"]) == "upgrade" &&
            boost::to_lower_copy(req.headers["Upgrade"]) == "websocket") {
            ERR("Client attempted to make absolute-target WebSocket connection");
            if (conn->send(pw::HTTPResponse::make_basic("501", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
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
            if (conn->send(pw::HTTPResponse::make_basic("400", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        } else if (split_host.size() == 1) {
            split_host.push_back("80");
        }

        pn::UniqueSock<pn::tcp::Client> proxy;
        if (proxy->connect(split_host[0], split_host[1]) == PW_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        if (configure_socket(*proxy) == PW_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
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
        if (proxy->send(proxied_req_data.data(), proxied_req_data.size()) == PW_ERROR) {
            ERR_NET;
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        pw::HTTPResponse resp;
        if (resp.parse(*proxy) == PW_ERROR) {
            ERR_WEB;
            ERR("Failed to parse HTTP response");
            if (conn->send(pw::HTTPResponse::make_basic("500", {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version)) == PW_ERROR)
                ERR_WEB;
            return;
        }

        resp.headers.insert(PROXY_CONNECTION_CLOSE);
        pw::HTTPHeaders::const_iterator transfer_encoding_it;
        if ((transfer_encoding_it = resp.headers.find("Transfer-Encoding")) != resp.headers.end()) {
            resp.headers.erase(transfer_encoding_it);
        }

        std::vector<char> proxied_resp_data = resp.build();
        if (conn->send(proxied_resp_data.data(), proxied_resp_data.size()) == PW_ERROR) {
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

    pn::UniqueSock<pn::tcp::Server> server;
    if (server->bind("0.0.0.0", argv[1]) == PW_ERROR) {
        ERR_NET;
        return 1;
    }

    if (configure_socket(*server) == PW_ERROR) {
        ERR_NET;
        ERR("Failed to configure server socket");
        return 1;
    }

    INFO("Proxy server listening on port " << argv[1]);
    if (server->listen([](pn::tcp::Connection& conn, void*) -> bool {
            pw::threadpool.schedule([conn](void* data) {
                init_conn(pn::SharedSock<pw::Connection>(conn));
            });
            return true;
        }) == PW_ERROR) {
        ERR_NET;
        return 1;
    }

    pn::quit();
    return 0;
}
