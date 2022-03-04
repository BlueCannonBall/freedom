#include "Polynet/polynet.hpp"
#include <thread>

std::string get_network_error() {
    switch (pn::get_last_error()) {
        case PN_ESOCKET: {
            return pn::socket_strerror(pn::get_last_socket_error());
        }

        case PN_EAI: {
            return pn::gai_strerror(pn::get_last_gai_error());
        }

        case PN_ESUCCESS:
        case PN_EBADADDRS: {
            return pn::strerror(pn::get_last_error());
        }

        default: {
            return "Unknown error";
        }
    }
}

void init_conn(pn::tcp::Connection client) {
    char method[9];
    client.recv(method, 8, MSG_WAITALL);
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

        if (c == '.') {
            if (hit_port || host.size() == 0) {
                char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                client.send(response, sizeof(response) - 1);
                client.close();
                return;
            }
            hit_port = true;
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
        std::cerr << "CLI error: Missing arguments\n";
        return 1;
    }

    pn::tcp::Server server;
    if (server.bind("0.0.0.0", argv[1]) == PN_ERROR) {
        std::cerr << "Network error: " << get_network_error() << std::endl;
        return 1;
    }

    if (server.listen([](pn::tcp::Connection& client, void*) -> bool {
        std::thread(init_conn, client).detach();

        return true;
    }, 128) == PN_ERROR) {
        std::cerr << "Network error: " << get_network_error() << std::endl;
        return 1;
    }

    return 0;
}