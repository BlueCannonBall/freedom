#include "Polynet/polynet.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <csignal>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#ifndef _WIN32
    #include <cerrno>
#endif

#define INFO(msg)                                           \
    print_lock.lock();                                      \
    std::cout << "[" << __FILE__ << ":" << __LINE__ << "] " \
              << "Info: " << msg << std::endl;              \
    print_lock.unlock()
#define ERR(msg)                                            \
    print_lock.lock();                                      \
    std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
              << "Error: " << msg << std::endl;             \
    print_lock.unlock()
#define ERR_NET                                                              \
    print_lock.lock();                                                       \
    std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] "                  \
              << "Network error: " << pn::universal_strerror() << std::endl; \
    print_lock.unlock()
#define ERR_CLI(msg)                                        \
    print_lock.lock();                                      \
    std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] " \
              << "CLI error: " << msg << std::endl;         \
    print_lock.unlock()

struct case_insensitive_comparer {
    bool operator()(const std::string& a, const std::string& b) const {
        return boost::iequals(a, b);
    }
};

struct case_insensitive_hasher {
    size_t operator()(const std::string& key) const {
        std::string key_copy = boost::to_lower_copy(key);
        return std::hash<std::string>()(key_copy);
    }
};

typedef std::unordered_map<std::string, std::string, case_insensitive_hasher, case_insensitive_comparer> HTTPHeaders;

std::mutex print_lock;
std::string password;

std::string decode64(const std::string& s) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(s)), It(std::end(s))), [](char c) {
        return c == '\0';
    });
}

template <typename T>
std::vector<char> read_until(T& conn, const std::string& end_sequence) {
    std::vector<char> buf;

    size_t search_pos = 0;
    for (;;) {
        char c;
        ssize_t read_result;
        if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
            break;
        } else if (read_result == PN_ERROR) {
            ERR_NET;
            break;
        }

        if (c == end_sequence[search_pos]) {
            if (++search_pos == end_sequence.size()) {
                break;
            }
        } else {
            buf.push_back(c);
            search_pos = 0;

            if (c == end_sequence[search_pos]) {
                if (++search_pos == end_sequence.size()) {
                    break;
                }
            }
        }
    }

    return buf;
}

class HTTPRequest {
public:
    std::string method;
    std::string target;
    std::string http_version;
    HTTPHeaders headers;
    std::vector<char> body;

    std::vector<char> build() {
        std::vector<char> ret;

        ret.insert(ret.end(), this->method.begin(), this->method.end());
        ret.push_back(' ');
        ret.insert(ret.end(), this->target.begin(), this->target.end());
        ret.push_back(' ');
        ret.insert(ret.end(), this->http_version.begin(), this->http_version.end());
        ret.insert(ret.end(), {'\r', '\n'});

        for (const auto& header : this->headers) {
            ret.insert(ret.end(), header.first.begin(), header.first.end());
            ret.insert(ret.end(), {':', ' '});
            ret.insert(ret.end(), header.second.begin(), header.second.end());
            ret.insert(ret.end(), {'\r', '\n'});
        }

        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    template <typename T>
    int parse(T& stream) {
        auto method = read_until(stream, " ");
        if (method.empty()) {
            ERR("Request method not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->method = std::string(method.begin(), method.end());

        auto target = read_until(stream, " ");
        if (target.empty()) {
            ERR("Request target not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->target = std::string(target.begin(), target.end());

        auto http_version = read_until(stream, "\r\n");
        if (http_version.empty()) {
            ERR("HTTP version not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->http_version = std::string(http_version.begin(), http_version.end());

        for (;;) {
            auto header_name = read_until(stream, ": ");
            if (header_name.empty()) {
                ERR("HTTP request header name terminated unexpectedly");
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return 1;
            }

            auto header_value = read_until(stream, "\r\n");
            boost::trim_left(header_value);
            if (header_value.empty()) {
                ERR("HTTP request header value terminated unexpectedly");
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return 1;
            }

            {
                std::string string_header_name = std::string(header_name.begin(), header_name.end());
                std::string string_header_value = std::string(header_value.begin(), header_value.end());
                this->headers[std::move(string_header_name)] = std::move(string_header_value);
            }

            char end_check_buf[2];
            ssize_t read_result;
#ifdef _WIN32
            for (;;) {
                if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK)) == 0) {
                    ERR("Connection unexpectedly closed");
                    return 1;
                } else if (read_result == PN_ERROR) {
                    ERR_NET;
                    char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                    if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                        ERR_NET;
                    }
                    return 1;
                } else if (read_result == sizeof(end_check_buf)) {
                    break;
                }
            }
#else
            if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK | MSG_WAITALL)) == 0) {
                ERR("Connection unexpectedly closed");
                return 1;
            } else if (read_result == PN_ERROR) {
                ERR_NET;
                char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return 1;
            }
#endif

            if (memcmp("\r\n", end_check_buf, sizeof(end_check_buf)) == 0) {
                if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL)) == 0) {
                    ERR("Connection unexpectedly closed");
                    return 1;
                } else if (read_result == PN_ERROR) {
                    ERR_NET;
                    char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                    if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                        ERR_NET;
                    }
                    return 1;
                }

                break;
            }
        }

        if (headers.find("Content-Length") != headers.end()) {
            this->body.resize(std::stoi(headers["Content-Length"]));

            ssize_t read_result;
            if ((read_result = stream.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                ERR("Connection unexpectedly closed");
                return 1;
            } else if (read_result == PN_ERROR) {
                ERR_NET;
                char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return 1;
            }
        }

        return 0;
    }
};

void route(pn::tcp::Connection a, pn::tcp::Connection b) {
    char buf[UINT16_MAX];
    while (a.is_valid() && b.is_valid()) {
        ssize_t read_result;
        if ((read_result = a.recv(buf, sizeof(buf))) == 0) {
            INFO("Connection closed");
            break;
        } else if (read_result == PN_ERROR) {
#ifdef _WIN32
            if (pn::get_last_socket_error() != WSAENOTSOCK) {
#else
            if (pn::get_last_socket_error() != EBADF) {
#endif
                ERR_NET;
            }
            break;
        }

        if (b.send(buf, read_result) == PN_ERROR) {
#ifdef _WIN32
            if (pn::get_last_socket_error() != WSAENOTSOCK) {
#else
            if (pn::get_last_socket_error() != EBADF) {
#endif
                ERR_NET;
            }
            break;
        }
    }
}

void init_conn(pn::tcp::Connection conn) {
    HTTPRequest request;
    if (request.parse(conn) != 0) {
        return;
    }

    if (!password.empty()) {
        if (request.headers.find("Proxy-Authorization") == request.headers.end()) {
            ERR("Authentication not provided");
            char response[] = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        } else {
            std::vector<std::string> split_auth;
            boost::split(split_auth, std::move(request.headers["Proxy-Authorization"]), isspace);
            if (boost::to_lower_copy(split_auth[0]) != "basic") {
                ERR("Authorization failed: Unsupported authentication schema");
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return;
            }

            std::string decoded_auth = decode64(split_auth[1]);
            std::vector<std::string> split_decoded_auth;
            boost::split(split_decoded_auth, std::move(decoded_auth), boost::is_any_of(":"));
            if (split_decoded_auth[1] != password) {
                ERR("Authorization failed: Incorrect password");
                char response[] = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
                if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return;
            }

            INFO("User \"" << split_decoded_auth[0] << "\" successfully authorized");
        }
    }

    if (request.method == "CONNECT") {
        if (boost::starts_with(request.target, "http://") || boost::starts_with(request.target, "https://")) {
            ERR("Client attempted use absolute path in HTTP CONNECT request");
            return;
        }

        std::vector<std::string> split_target;
        boost::split(split_target, std::move(request.target), boost::is_any_of(":"));

        if (split_target.size() > 2) {
            ERR("Failed to parse target of CONNECT request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        } else if (split_target.size() == 1) {
            split_target.push_back("80");
        }

        pn::tcp::Client proxy;
        if (proxy.connect(split_target[0], split_target[1]) == PN_ERROR) {
            ERR_NET;
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        char response[] = "HTTP/1.1 200 OK\r\n\r\n";
        if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
            ERR_NET;
            return;
        }

        INFO("Routing connection to " << split_target[0] << ":" << split_target[1]);
        std::thread(route, conn, proxy).detach();
        std::thread(route, proxy, conn).detach();
        conn.release();
        proxy.release();
    } else {
        size_t protocol_len;
        if (boost::starts_with(request.target, "http://")) {
            protocol_len = 7;
        } else if (boost::starts_with(request.target, "ws://")) {
            protocol_len = 5;
        } else {
            ERR("Client (possibly) attempted to make regular HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        std::string host(request.target.size() - protocol_len, ' ');
        strcpy(&host[0], request.target.data() + protocol_len);
        std::string::size_type pos;
        if ((pos = host.find('/')) != std::string::npos) {
            request.target.resize(host.size() - pos);
            strcpy(&request.target[0], &host[pos]);
            host.resize(pos);
        }

        std::vector<std::string> split_host;
        boost::split(split_host, host, boost::is_any_of(":"));

        if (split_host.size() > 2) {
            ERR("Failed to parse host of absolute target HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        } else if (split_host.size() == 1) {
            split_host.push_back("80");
        }

        pn::tcp::Client proxy;
        if (proxy.connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        for (auto it = request.headers.cbegin(); it != request.headers.cend();) {
            if (boost::starts_with(boost::to_lower_copy((*it).first), "proxy-")) {
                request.headers.erase(it++);
            } else {
                ++it;
            }
        }

        request.headers["Host"] = std::move(host);

        bool is_websocket_connection = false; // Other upgrades are NOT SUPPORTED
        if (request.http_version == "HTTP/1.1" &&
            request.method == "GET" &&
            request.headers.find("Upgrade") != request.headers.end() &&
            request.headers.find("Connection") != request.headers.end() &&
            boost::to_lower_copy(request.headers["Connection"]) == "upgrade" &&
            boost::to_lower_copy(request.headers["Upgrade"]) == "websocket") {
            is_websocket_connection = true;
        } else {
            request.headers["Connection"] = "close";
        }

        request.http_version = "HTTP/1.1";

        std::vector<char> proxied_request_data = request.build();
        if (proxy.send(proxied_request_data.data(), proxied_request_data.size()) == PN_ERROR) {
            ERR_NET;
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        if (!is_websocket_connection) {
            INFO("Routing HTTP request to " << split_host[0] << ":" << split_host[1]);
            route(std::move(proxy), std::move(conn));
        } else {
            INFO("Routing WebSocket connection to " << split_host[0] << ":" << split_host[1]);
            std::thread(route, conn, proxy).detach();
            std::thread(route, proxy, conn).detach();
            conn.release();
            proxy.release();
        }
    }
}

int main(int argc, char** argv) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    if (argc < 2) {
        ERR_CLI("Missing arguments");
        return 1;
    }

    if (argc >= 3) {
        password = argv[2];
    }

    std::cout << "Cross-platform networking brought to you by:" << std::endl;
    pn::init(true);

    pn::tcp::Server server;
    if (server.bind("0.0.0.0", argv[1]) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    const int value = 1;
    if (server.setsockopt(IPPROTO_TCP, TCP_NODELAY, (const char*) &value, sizeof(int)) == PN_ERROR) {
        ERR_NET;
        return 1;
    }
#ifdef __linux__
    if (server.setsockopt(IPPROTO_TCP, TCP_QUICKACK, (const char*) &value, sizeof(int)) == PN_ERROR) {
        ERR_NET;
        return 1;
    }
#endif

    INFO("Proxy server listening on port " << argv[1]);
    if (server.listen([](pn::tcp::Connection& conn, void*) -> bool {
            std::thread(init_conn, std::move(conn)).detach();
            return true;
        },
            128) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    pn::quit();
    return 0;
}
