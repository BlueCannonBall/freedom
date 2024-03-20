#ifndef _SQLITE_HPP
#define _SQLITE_HPP

#include <iostream>
#include <optional>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace sqlite {
    typedef std::vector<char> Blob;
    typedef double Double;
    typedef int Int;
    typedef sqlite3_int64 Int64;
    typedef std::string Text;

    inline std::string errstr(int error) {
        return sqlite3_errstr(error);
    }

    using Error = std::runtime_error;

    class Connection {
    protected:
        friend class Statement;

        sqlite3* raw_conn = nullptr;

    public:
        Connection(const std::string& filename, int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX) {
            int result;
            if ((result = sqlite3_open_v2(filename.c_str(), &raw_conn, flags, nullptr)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }
        Connection(Connection&& conn) {
            *this = std::move(conn);
        }

        Connection& operator=(Connection&& conn) {
            if (this != &conn) {
                sqlite3_close(std::exchange(raw_conn, conn.raw_conn));
                conn.raw_conn = nullptr;
            }
            return *this;
        }

        ~Connection() {
            sqlite3_close(raw_conn);
        }

        int errcode() const {
            return sqlite3_errcode(raw_conn);
        }

        std::string errmsg() const {
            return sqlite3_errmsg(raw_conn);
        }

        void exec(const std::string& sql) {
            int result;
            if ((result = sqlite3_exec(raw_conn, sql.c_str(), nullptr, nullptr, nullptr)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void exec_nothrow(const std::string& sql) {
            sqlite3_exec(raw_conn, sql.c_str(), nullptr, nullptr, nullptr);
        }
    };

    template <typename... Ts>
    using Row = std::tuple<Ts...>;

    template <typename... Ts>
    using Table = std::vector<Row<Ts...>>;

    class Statement {
    protected:
        template <size_t I, typename... Ts>
        void push_value(Row<Ts...>& row) {
            typename std::tuple_element<I, Row<Ts...>>::type value;
            get_column(value, I);
            std::get<I>(row) = value;
        }

        template <typename... Ts, size_t... Is>
        Row<Ts...> make_row(std::index_sequence<Is...>) {
            Row<Ts...> ret;
            (push_value<Is, Ts...>(ret), ...);
            return ret;
        }

        void get_column(Blob& ret, size_t index) const {
            const char* raw_blob = (const char*) sqlite3_column_blob(raw_stmt, index);
            ret = Blob(raw_blob, raw_blob + sqlite3_column_bytes(raw_stmt, index));
        }

        void get_column(Double& ret, size_t index) const {
            ret = sqlite3_column_double(raw_stmt, index);
        }

        void get_column(Int& ret, size_t index) const {
            ret = sqlite3_column_int(raw_stmt, index);
        }

        void get_column(Int64& ret, size_t index) const {
            ret = sqlite3_column_int64(raw_stmt, index);
        }

        void get_column(Text& ret, size_t index) const {
            const char* raw_text = (const char*) sqlite3_column_text(raw_stmt, index);
            ret = Text(raw_text, raw_text + sqlite3_column_bytes(raw_stmt, index));
        }

        template <typename T>
        void get_column(std::optional<T>& ret, size_t index) {
            if (sqlite3_column_type(raw_stmt, index) == SQLITE_NULL) {
                ret = std::nullopt;
            } else {
                T value;
                get_column(value, index);
                ret = value;
            }
        }

        sqlite3_stmt* raw_stmt = nullptr;

    public:
        Statement(const Connection& conn, const std::string& sql) {
            int result;
            if ((result = sqlite3_prepare_v2(conn.raw_conn, sql.c_str(), -1, &raw_stmt, nullptr)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }
        Statement(Statement&& stmt) {
            *this = std::move(stmt);
        }

        Statement& operator=(Statement&& stmt) {
            if (this != &stmt) {
                sqlite3_finalize(std::exchange(raw_stmt, stmt.raw_stmt));
                stmt.raw_stmt = nullptr;
            }
            return *this;
        }

        ~Statement() {
            sqlite3_finalize(raw_stmt);
        }

        void bind(const Blob& value, size_t index) {
            int result;
            if ((result = sqlite3_bind_blob(raw_stmt, index, value.data(), value.size(), SQLITE_TRANSIENT)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void bind(Double value, size_t index) {
            int result;
            if ((result = sqlite3_bind_double(raw_stmt, index, value)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void bind(Int value, size_t index) {
            int result;
            if ((result = sqlite3_bind_int(raw_stmt, index, value)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void bind(Int64 value, size_t index) {
            int result;
            if ((result = sqlite3_bind_int64(raw_stmt, index, value)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void bind(const Text& value, size_t index) {
            int result;
            if ((result = sqlite3_bind_text(raw_stmt, index, value.c_str(), -1, SQLITE_TRANSIENT)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void reset() {
            int result;
            if ((result = sqlite3_reset(raw_stmt)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        void clear_bindings() {
            int result;
            if ((result = sqlite3_clear_bindings(raw_stmt)) != SQLITE_OK) {
                throw Error(errstr(result));
            }
        }

        template <typename... Us>
        Table<Us...> exec() {
            Table<Us...> ret;
            while (sqlite3_step(raw_stmt) != SQLITE_DONE) {
                ret.push_back(make_row<Us...>(std::make_index_sequence<sizeof...(Us)>()));
            }
            reset();
            return ret;
        }

        void exec_void() {
            while (sqlite3_step(raw_stmt) != SQLITE_DONE) {}
            reset();
        }
    };
} // namespace sqlite

#endif
