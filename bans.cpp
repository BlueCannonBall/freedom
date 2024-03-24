#include "bans.hpp"
#include "sqlite.hpp"
#include "util.hpp"
#include <algorithm>
#include <iterator>

namespace bans {
    sqlite::Connection db("bans.db");

    void init_table() {
        db.exec("CREATE TABLE IF NOT EXISTS bans (username TEXT UNIQUE)");
    }

    std::vector<std::string> get_all_bans() {
        thread_local sqlite::Statement stmt(db, "SELECT username FROM bans ORDER BY username");
        auto table = stmt.exec<sqlite::Text>();
        stmt.reset();

        std::vector<std::string> ret;
        ret.reserve(table.size());
        std::transform(table.begin(), table.end(), std::back_inserter(ret), [](const auto& row) {
            return std::get<0>(row);
        });
        return ret;
    }

    void ban(const std::string& username) {
        thread_local sqlite::Statement stmt(db, "INSERT OR IGNORE INTO bans (username) VALUES (?)");
        stmt.bind(username, 1);
        stmt.exec_void();
        INFO("User " << std::quoted(username) << " has been BANNED");
        stmt.reset();
    }

    void unban(const std::string& username) {
        thread_local sqlite::Statement stmt(db, "DELETE FROM bans WHERE username = ?");
        stmt.bind(username, 1);
        stmt.exec_void();
        INFO("User " << std::quoted(username) << " has been unbanned");
        stmt.reset();
    }

    bool is_banned(const std::string& username) {
        thread_local sqlite::Statement stmt(db, "SELECT username FROM bans WHERE username = ?");
        stmt.bind(username, 1);
        auto table = stmt.exec<sqlite::Text>();
        stmt.reset();
        return !table.empty();
    }
} // namespace bans
