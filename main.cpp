#include "Polynet/polynet.hpp"
#include <thread>

#define ERR_NET std::cerr << "Network error: " << pn::universal_strerror() << std::endl
#define ERR_CLI(msg) std::cerr << "CLI error: " << msg << std::endl

std::pair<char*, size_t> read_until(pn::tcp::Connection& conn, char end_char) {
    size_t buf_size = 0;
    char* buf = (char*) malloc(buf_size);

    while (true) {
        char c;
        conn.recv(&c, 1);

        if (c != end_char) {
            buf = (char*) realloc(buf, ++buf_size);
            buf[buf_size - 1] = c;
        } else {
            break;
        }
    }

    return {buf, buf_size};
}

void route(pn::tcp::Connection a, pn::tcp::Connection b) {
    while (true) {
        char buf[UINT16_MAX];
        auto result = a.recv(NULL, UINT16_MAX);
        b.send(buf, result);
    }
}

void init_conn(pn::tcp::Connection client) {
    char method[9];
    if (client.recv(method, 8, MSG_WAITALL) == 0) {

    }
    method[8] = '\0';

    if (strcmp(method, "CONNECT ")) {
        char response[] = "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n\r\n";
        client.send(response, sizeof(response) - 1);
        client.close();
        return;
    }

    std::string host;
    std::string port;
    bool hit_port = false;

    while (true) {
        char c;
        client.recv(&c, 1, MSG_WAITALL);

        if (c == ':') {
            if (hit_port || host.size() == 0) {
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                client.send(response, sizeof(response) - 1);
                client.close();
                return;
            }
            
            hit_port = true;
            continue;
        }

        if (!hit_port) {
            host += c;
        } else {
            port += c;
        }
    }

    char response[] = "HTTP/1.1 200 OK\r\n\r\n";
    client.send(response, sizeof(response) - 1);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        ERR_CLI("Missing arguments");
        return 1;
    }

    pn::tcp::Server server;
    if (server.bind("0.0.0.0", argv[1]) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    if (server.listen([](pn::tcp::Connection& client, void*) -> bool {
        std::thread(init_conn, client).detach();
        return true;
    }, 128) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    return 0;
}