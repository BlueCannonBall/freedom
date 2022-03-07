#include "Polynet/polynet.hpp"
#include <boost/algorithm/string.hpp>
#include <csignal>
#include <cstring>
#include <mutex>
#include <netinet/in.h>
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
        std::string key_copy(key);
        boost::to_lower(key_copy);
        return std::hash<std::string>()(key_copy);
    }
};

typedef std::unordered_map<std::string, std::string, case_insensitive_hasher, case_insensitive_comparer> HTTPHeaders;

std::mutex print_lock;

template <typename T>
std::vector<char> read_until(T& conn, const std::string& end_sequence) {
    std::vector<char> buf;

    size_t search_pos = 0;
    while (true) {
        char c;
        ssize_t read_result;
        if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
            break;
        } else if (read_result == PN_ERROR) {
            ERR_NET;
            break;
        }

        if (c == end_sequence[search_pos]) {
            if (++search_pos == end_sequence.length()) {
                break;
            }
        } else {
            buf.push_back(c);
            search_pos = 0;

            if (c == end_sequence[search_pos]) {
                if (++search_pos == end_sequence.length()) {
                    break;
                }
            }
        }
    }

    return buf;
}

class HTTPRequestParser {
public:
    std::string method;
    std::string target;
    std::string http_version;
    HTTPHeaders headers;
    std::vector<char> body;

    template <typename T>
    int parse(T& stream) {
        auto method = read_until(stream, " ");
        if (method.size() == 0) {
            ERR("Request method not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->method = std::string(method.begin(), method.end());

        auto target = read_until(stream, " ");
        if (target.size() == 0) {
            ERR("Request target not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->target = std::string(target.begin(), target.end());

        auto http_version = read_until(stream, "\r\n");
        if (http_version.size() == 0) {
            ERR("HTTP version not found in HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return 1;
        }
        this->http_version = std::string(http_version.begin(), http_version.end());

        while (true) {
            auto header_name = read_until(stream, ": ");
            if (header_name.size() == 0) {
                ERR("HTTP request header name terminated unexpectedly");
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                if (stream.send(response, sizeof(response) - 1) == PN_ERROR) {
                    ERR_NET;
                }
                return 1;
            }

            auto header_value = read_until(stream, "\r\n");
            if (header_value.size() == 0) {
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
                this->headers[string_header_name] = string_header_value;
            }

            char end_check_buf[2];
            ssize_t read_result;
            if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL | MSG_PEEK)) == 0) {
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

class HTTPRequestBuilder {
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
};

void route(pn::tcp::Connection a, pn::tcp::Connection b) {
    char buf[UINT16_MAX];
    while (a.is_valid() && b.is_valid()) {
        ssize_t read_result;
        if ((read_result = a.recv(buf, sizeof(buf))) == 0) {
            INFO("Connection closed");
            b.close();
            a.close();
            break;
        } else if (read_result == PN_ERROR) {
            if (pn::get_last_error() == PN_ESOCKET) {
#ifdef _WIN32
                if (pn::get_last_socket_error() != WSAENOTSOCK) {
#else
                if (pn::get_last_socket_error() != EBADF) {
#endif
                    ERR_NET;
                }
            } else {
                ERR_NET;
            }
            b.close();
            a.close();
            break;
        }

        ssize_t c;
        if ((c = b.send(buf, read_result)) == PN_ERROR) {
            if (pn::get_last_error() == PN_ESOCKET) {
#ifdef _WIN32
                if (pn::get_last_socket_error() != WSAENOTSOCK) {
#else
                if (pn::get_last_socket_error() != EBADF) {
#endif
                    ERR_NET;
                }
            } else {
                ERR_NET;
            }
            a.close();
            b.close();
            break;
        }
    }
}

void init_conn(pn::tcp::Connection conn) {
    HTTPRequestParser parser;
    if (parser.parse(conn) != 0) {
        ERR("Failed to parse HTTP request");
        return;
    }

    if (parser.method == "CONNECT") {
        if (boost::starts_with(parser.target, "http://") || boost::starts_with(parser.target, "https://")) {
            ERR("Client attempted use absolute path in HTTP CONNECT request");
            return;
        }

        std::vector<std::string> split_target;
        boost::split(split_target, parser.target, boost::is_any_of(":"));

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
        return;
    } else {
        if (boost::starts_with(parser.target, "https://")) {
            ERR("Client attempted to use HTTPS in absolute path request");
            return;
        } else if (!boost::starts_with(parser.target, "http://")) {
            ERR("Client attempted to make regular HTTP request");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        HTTPRequestBuilder builder;

        std::string host(parser.target.size() - 7, ' ');
        strcpy(&host[0], parser.target.data() + 7);
        std::string::size_type pos;
        if ((pos = host.find('/')) != std::string::npos) {
            builder.target.resize(host.size() - pos);
            strcpy(&builder.target[0], &host[pos]);
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

        builder.method = std::move(parser.method);
        builder.http_version = std::move(parser.http_version);
        builder.body = std::move(parser.body);

        for (const auto& header : parser.headers) {
            auto lowercase_header = boost::to_lower_copy(header.first);
            if (lowercase_header == "host" || boost::starts_with(lowercase_header, "proxy-")) {
                continue;
            }

            builder.headers.insert(header);
        }
        builder.headers["Host"] = std::move(host);

        pn::tcp::Client proxy;
        if (proxy.connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        auto new_request = builder.build();
        if (proxy.send(new_request.data(), new_request.size()) == PN_ERROR) {
            ERR_NET;
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            if (conn.send(response, sizeof(response) - 1) == PN_ERROR) {
                ERR_NET;
            }
            return;
        }

        INFO("Routing HTTP request to " << split_host[0] << ":" << split_host[1]);
        conn.shutdown(PN_SD_RECEIVE);
        std::thread(route, std::move(proxy), std::move(conn)).detach();
        return;
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        ERR_CLI("Missing arguments");
        return 1;
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
    if (server.setsockopt(IPPROTO_TCP, TCP_QUICKACK, (const char*) &value, sizeof(int)) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

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