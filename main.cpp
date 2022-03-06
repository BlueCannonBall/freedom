#include "Polynet/polynet.hpp"
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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

std::mutex print_lock;

size_t send_all(pn::tcp::Connection& conn, const char* buf, size_t len) {
    auto buf_pos = (const char*) buf;
    ssize_t bytes_written;

    while (len) {
        if ((bytes_written = conn.send(buf_pos, len)) == PN_ERROR) {
            ERR_NET;
            break;
        }

        buf_pos += bytes_written;
        len -= bytes_written;
    }

    return buf_pos - (const char*) buf;
}

size_t read_until(pn::tcp::Connection& conn, const std::string& end_sequence, char** buf) {
    size_t buf_size = 0;
    *buf = (char*) malloc(buf_size);

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
            *buf = (char*) realloc(*buf, ++buf_size);
            (*buf)[buf_size - 1] = c;
            search_pos = 0;

            if (c == end_sequence[search_pos]) {
                if (++search_pos == end_sequence.length()) {
                    break;
                }
            }
        }
    }

    return buf_size;
}

void route(pn::tcp::Connection a, pn::tcp::Connection b) {
    INFO("Routing connection");

    char buf[UINT16_MAX];
    while (true) {
        ssize_t read_result;
        if ((read_result = a.recv(buf, sizeof(buf))) == 0) {
            INFO("Connection closed");
            b.close();
            a.close();
            break;
        } else if (read_result == PN_ERROR) {
            ERR_NET;
            b.close();
            a.close();
            break;
        }

        if (send_all(b, buf, read_result) != read_result) {
            ERR("Failed to send message");
            a.close();
            b.close();
            break;
        }
    }
}

void init_conn(pn::tcp::Connection conn) {
    char* method;
    size_t method_len = read_until(conn, " ", &method);

    if (method_len != 7) {
        ERR("Invalid method");
        char response[] = "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(method);
        return;
    } else if (memcmp(method, "CONNECT", 7) != 0) {
        ERR("Invalid method");
        char response[] = "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(method);
        return;
    }
    free(method);

    char* host;
    char* port;
    size_t host_len;
    size_t port_len;
    if ((host_len = read_until(conn, ":", &host)) == 0) {
        ERR("Host not found");
        char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(host);
        return;
    }
    if ((port_len = read_until(conn, " ", &port)) == 0) {
        ERR("Port not found");
        char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(host);
        free(port);
        return;
    }

    char* http_version;
    size_t http_version_len;
    if ((http_version_len = read_until(conn, "\r\n", &http_version)) == 0) {
        ERR("HTTP version not found");
        char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(host);
        free(port);
        free(http_version);
        return;
    }
    free(http_version);

    // Read headers
    while (true) {
        char* header;
        size_t header_len;
        if ((header_len = read_until(conn, "\r\n", &header)) == 0) {
            ERR("Header name terminated unexpectedly");
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send_all(conn, response, sizeof(response) - 1);
            conn.close();
            free(host);
            free(port);
            free(header);
            return;
        }

        // Use headers or something, idk
        // ...

        free(header);

        char end_check_buf[2];
        conn.recv(end_check_buf, 2, MSG_WAITALL | MSG_PEEK);
        if (memcmp(end_check_buf, "\r\n", 2) == 0) {
            conn.recv(end_check_buf, 2, MSG_WAITALL);
            break;
        }
    }

    host = (char*) realloc(host, host_len + 1);
    port = (char*) realloc(port, port_len + 1);
    host[host_len] = '\0';
    port[port_len] = '\0';

    pn::tcp::Client proxy;
    if (proxy.connect(host, port) == PN_ERROR) {
        char response[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        send_all(conn, response, sizeof(response) - 1);
        conn.close();
        free(host);
        free(port);
        return;
    }
    free(host);
    free(port);

    char response[] = "HTTP/1.1 200 OK\r\n\r\n";
    if (send_all(conn, response, sizeof(response) - 1) != sizeof(response) - 1) {
        conn.close();
        return;
    }

    std::thread(route, conn, proxy).detach();
    std::thread(route, proxy, conn).detach();
    conn.release();
    proxy.release();
}

int main(int argc, char** argv) {
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