#include "Polyweb/polyweb.hpp"
#include "adblock.hpp"
#include "bans.hpp"
#include "pages.hpp"
#include "util.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Spinner.H>
#include <FL/Fl_Window.H>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

std::string port;
std::string password;
std::string admin_password;

std::mutex deauthenticated_users_mutex;
std::unordered_set<std::string> deauthenticated_users;

class SetupWindow final : public Fl_Window {
    Fl_Spinner* port_input;
    Fl_Check_Button* accounts_check_button;
    Fl_Secret_Input* password_input;
    Fl_Secret_Input* admin_password_input;
    Fl_Button* start_button;
    Fl_Button* cancel_button;

    bool setup_complete = false;

public:
    SetupWindow(const char* title = "Freedom Setup"):
        Fl_Window(350, 165, title) {
        begin();
        port_input = new Fl_Spinner(140, 10, 80, 25, "Port:");
        accounts_check_button = new Fl_Check_Button(140, 40, 200, 25, "User accounts");
        password_input = new Fl_Secret_Input(140, 70, 200, 25, "Password:");
        admin_password_input = new Fl_Secret_Input(140, 100, 200, 25, "Admin password:");
        start_button = new Fl_Button(205, 130, 65, 25, "Start");
        cancel_button = new Fl_Button(275, 130, 65, 25, "Cancel");
        end();

        port_input->type(FL_INT_INPUT);
        port_input->minimum(0);
        port_input->maximum(65535);
        port_input->value(8000);

        accounts_check_button->callback([](Fl_Widget* widget, void* data) {
            auto setup_window = (SetupWindow*) data;
            auto accounts_check_button = (Fl_Check_Button*) widget;
            if (accounts_check_button->value()) {
                setup_window->password_input->activate();
                setup_window->admin_password_input->activate();
            } else {
                setup_window->password_input->deactivate();
                setup_window->admin_password_input->deactivate();
            }
        },
            this);

        password_input->deactivate();
        admin_password_input->deactivate();

        start_button->callback([](Fl_Widget* widget, void* data) {
            auto setup_window = (SetupWindow*) data;
            port = std::to_string((int) setup_window->port_input->value());
            if (setup_window->accounts_check_button->value()) {
                password = setup_window->password_input->value();
                admin_password = setup_window->admin_password_input->value();
            }
            setup_window->hide();
            setup_window->setup_complete = true;
        },
            this);

        cancel_button->callback([](Fl_Widget* widget, void* data) {
            auto setup_window = (SetupWindow*) data;
            setup_window->hide();
        },
            this);
    }

    bool run() {
        show();
        while (shown()) {
            Fl::wait();
        }
        Fl::check();
        return setup_complete;
    }
};

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
    Timer<> timer([](auto duration) {
        std::lock_guard<std::mutex> lock(pages::stats_mutex);
        pages::response_time += std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        ++pages::requests_handled;
    });

    if (set_socket_timeout(*conn, std::chrono::seconds(30)) == PN_ERROR) {
        ERR_NET;
        ERR("Failed to configure socket");
        conn->send_basic(500, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE});
        timer.release();
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
        timer.release();
        return;
    }

    {
        std::lock_guard<std::mutex> lock(pages::stats_mutex);
        decltype(pages::activity)::iterator date_it;
        std::string date = get_date();
        if ((date_it = pages::activity.find(date)) != pages::activity.end()) {
            ++date_it->second;
        } else {
            if (pages::activity.size() >= 180) {
                pages::activity.clear();
            }
            pages::activity[date] = 1;
        }
    }

    if (pw::string::to_lower_copy(req.target).find("mosyle") != std::string::npos) {
        INFO("Got connection to enemy target " << std::quoted(req.target));
        return;
    }

    bool admin = false;
    if (!password.empty()) {
        if (!req.headers.count("Proxy-Authorization")) {
            ERR("Authentication not provided");
            if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        } else {
            std::vector<std::string> split_auth = pw::string::split_and_trim(req.headers["Proxy-Authorization"], ' ');
            if (split_auth.size() < 2) {
                ERR("Authorization failed: Bad Proxy-Authorization header");
                if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                    ERR_WEB;
                }
                return;
            } else if (pw::string::to_lower_copy(split_auth[0]) != "basic") {
                ERR("Authorization failed: Unsupported authentication scheme");
                if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                    ERR_WEB;
                }
                return;
            } else {
                auto decoded_auth = pw::base64_decode(split_auth[1]);
                std::string decoded_auth_string(decoded_auth.begin(), decoded_auth.end());

                std::vector<std::string> split_decoded_auth = pw::string::split(decoded_auth_string, ':');
                if (split_decoded_auth.size() != 2 || split_decoded_auth[0].empty()) {
                    ERR("Authorization failed: Bad username:password combination");
                    if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                        ERR_WEB;
                    }
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(pages::stats_mutex);
                    decltype(pages::users)::iterator user_it;
                    if ((user_it = pages::users.find(split_decoded_auth[0])) != pages::users.end()) {
                        ++user_it->second;
                    } else {
                        if (pages::users.size() >= 1024) {
                            pages::users.clear();
                        }
                        pages::users[split_decoded_auth[0]] = 1;
                    }
                }
                {
                    std::unique_lock<std::mutex> lock(deauthenticated_users_mutex);
                    decltype(deauthenticated_users)::iterator user_it;
                    if ((user_it = deauthenticated_users.find(split_decoded_auth[0])) != deauthenticated_users.end()) {
                        deauthenticated_users.erase(user_it);
                        lock.unlock();
                        if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                            ERR_WEB;
                        }
                        return;
                    }
                }

                if (split_decoded_auth[1] == admin_password) {
                    admin = true;
                } else if (bans::is_banned(split_decoded_auth[0])) {
                    ERR("Authorization failed: Banned user " << std::quoted(split_decoded_auth[0]) << " tried to connect");
                    if (conn->send_basic(403, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                        ERR_WEB;
                    }
                    return;
                } else if (split_decoded_auth[1] != password) {
                    ERR("Authorization failed: Incorrect password");
                    if (conn->send_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                        ERR_WEB;
                    }
                    return;
                }

                if (admin) {
                    INFO("User " << std::quoted(split_decoded_auth[0]) << " successfully authorized as admin");
                } else {
                    INFO("User " << std::quoted(split_decoded_auth[0]) << " successfully authorized");
                }
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

        std::string reason;
        if (adblock::is_blacklisted(split_host[0], reason)) {
            INFO("Got connection to blacklisted hostname " << split_host[0]);
            pages::stats_mutex.lock();
            ++pages::ads_blocked;
            pages::stats_mutex.unlock();
            if (conn->send(pages::error_page(403, req.target, reason, req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        pn::SharedSocket<pn::tcp::Client> proxy;
        pn::tcp::BufReceiver proxy_buf_receiver;
        if (proxy->connect(split_host[0], split_host[1]) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to create proxy connection");
            if (conn->send(pages::error_page(404, req.target, pn::universal_strerror(), req.http_version)) == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if (configure_socket(*proxy) == PN_ERROR || set_socket_timeout(*proxy, std::chrono::hours(2)) == PN_ERROR) {
            ERR_NET;
            ERR("Failed to configure socket");
            if (conn->send(pages::error_page(500, req.target, pn::universal_strerror(), req.http_version)) == PN_ERROR) {
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
        if (password.empty() && req.target == "/stats") {
            if (conn->send(pages::stats_page(req.http_version), req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        pw::URLInfo url_info;
        if (url_info.parse(req.target) == PN_ERROR) {
            ERR_WEB;
            ERR("Failed to parse URL " << req.target);
            if (conn->send_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        pw::HTTPHeaders::const_iterator connection_it;
        if (req.method == "GET" &&
            req.http_version == "HTTP/1.1" &&
            (connection_it = req.headers.find("Connection")) != req.headers.end() &&
            pw::string::to_lower_copy(connection_it->second) == "upgrade") {
            ERR("Client attempted to upgrade with an absolute-form target request");
            if (conn->send_basic(501, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version, req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        std::string reason;
        if (adblock::is_blacklisted(url_info.hostname(), reason)) {
            INFO("Got connection to blacklisted hostname " << url_info.hostname());
            pages::stats_mutex.lock();
            ++pages::ads_blocked;
            pages::stats_mutex.unlock();
            if (conn->send(pages::error_page(403, url_info.host, reason, req.http_version), req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        if ((password.empty() || admin) &&
            (url_info.hostname() == "proxy.info" ||
                url_info.hostname() == "stats.gov")) {
            pw::HTTPResponse resp;
            if (url_info.path == "/") {
                resp = pages::stats_page(req.http_version);
            } else if (url_info.path == "/change_username") {
                resp = pw::HTTPResponse::make_basic(407, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE, PROXY_AUTHENTICATE_BASIC}, req.http_version);
            } else if (url_info.path == "/ban") {
                pw::QueryParameters::map_type::const_iterator username_it;
                if ((username_it = req.query_parameters->find("username")) != req.query_parameters->end()) {
                    bans::ban(username_it->second);
                    resp = pw::HTTPResponse::make_basic(200, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                } else {
                    resp = pw::HTTPResponse::make_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                }
            } else if (url_info.path == "/unban") {
                pw::QueryParameters::map_type::const_iterator username_it;
                if ((username_it = req.query_parameters->find("username")) != req.query_parameters->end()) {
                    bans::unban(username_it->second);
                    resp = pw::HTTPResponse::make_basic(200, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                } else {
                    resp = pw::HTTPResponse::make_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                }
            } else if (url_info.path == "/deauthenticate") {
                pw::QueryParameters::map_type::const_iterator username_it;
                if ((username_it = req.query_parameters->find("username")) != req.query_parameters->end()) {
                    deauthenticated_users_mutex.lock();
                    deauthenticated_users.insert(username_it->second);
                    deauthenticated_users_mutex.unlock();
                    resp = pw::HTTPResponse::make_basic(200, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                } else {
                    resp = pw::HTTPResponse::make_basic(400, {CONNECTION_CLOSE, PROXY_CONNECTION_CLOSE}, req.http_version);
                }
            } else {
                resp = pages::error_page(404, url_info.host, req.target + " does not exist", req.http_version);
            }

            if (conn->send(resp, req.method == "HEAD") == PN_ERROR) {
                ERR_WEB;
            }
            return;
        }

        // Prepare request
        req.target = url_info.path;
        req.headers.insert(CONNECTION_CLOSE);

        INFO("Routing HTTP request to " << url_info.host);

        pw::HTTPResponse resp;
        if (pw::fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", req, resp, {}, 0) == PN_ERROR) {
            ERR_WEB;
            ERR("Failed to perform HTTP request to " << url_info.host);
            if (conn->send(pages::error_page(500, url_info.host, pw::universal_strerror(), req.http_version)) == PN_ERROR) {
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
        SetupWindow setup_window;
        if (!setup_window.run()) {
            return 1;
        }
    } else {
        port = argv[1];
        if (argc >= 3) {
            password = argv[2];
            if (argc >= 4) {
                admin_password = argv[3];
            }
        }
    }

    std::cout << "Cross-platform networking brought to you by:\n";
    pn::init(true);

    pn::UniqueSocket<pn::tcp::Server> server;
    if (server->bind("0.0.0.0", port) == PN_ERROR) {
        ERR_NET;
        return 1;
    }

    if (configure_socket(*server) == PN_ERROR) {
        ERR_NET;
        ERR("Failed to configure server socket");
        return 1;
    }

    bans::init();
    adblock::register_blacklist(
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt",
        "This content is advertising.");
    adblock::register_blacklist(
        "https://hosts.anudeep.me/mirror/adservers.txt",
        "This content is advertising.");
    adblock::register_blacklist(
        "http://sbc.io/hosts/alternates/gambling-porn-only/hosts",
        "In the Name of Allah, the Most Compassionate, the Most Merciful. Porn and gambling are haram.");
    adblock::register_blacklist(
        "https://www.github.developerdan.com/hosts/lists/dating-services-extended.txt",
        "In the Name of Allah, the Most Compassionate, the Most Merciful. Dating is haram.");
    adblock::update_all_blacklists();

    INFO("Proxy server listening on port " << port);
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
