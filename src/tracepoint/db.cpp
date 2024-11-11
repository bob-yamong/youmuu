#include "db.h"

// 환경 변수에서 값을 가져오는 헬퍼 함수
std::string get_env_var(const char* var_name, const std::string& default_value) {
    const char* value = std::getenv(var_name);
    return value ? std::string(value) : default_value;
}

DBConnection::DBConnection() {
    try {
        // 환경 변수에서 DB 연결 정보 가져오기
        std::string host = get_env_var("POSTGRES_HOST", "localhost");
        std::string port = get_env_var("POSTGRES_PORT", "5432");
        std::string dbname = get_env_var("POSTGRES_DB", "yamong");
        std::string user = get_env_var("POSTGRES_USER", "yamong");
        std::string password = get_env_var("POSTGRES_PASSWORD", "yamong");

        // 연결 문자열 구성
        std::stringstream conn_string;
        conn_string << "dbname=" << dbname << " "
                   << "host=" << host << " "
                   << "port=" << port << " "
                   << "user=" << user << " "
                   << "password=" << password;

        conn = std::make_unique<pqxx::connection>(conn_string.str());
        
        // 초기 설정
        pqxx::work w(*conn);
        w.exec("SET synchronous_commit TO OFF");
        w.exec("SET client_encoding TO 'UTF8'");
        w.commit();

    } catch (const std::exception& e) {
        throw std::runtime_error("Database connection failed: " + std::string(e.what()));
    }
}

void DBConnection::ensure_connection() {
    try {
        if (!conn || !conn->is_open()) {
            // 재연결 시에도 환경 변수 사용
            std::string host = get_env_var("POSTGRES_HOST", "localhost");
            std::string port = get_env_var("POSTGRES_PORT", "5432");
            std::string dbname = get_env_var("POSTGRES_DB", "yamong");
            std::string user = get_env_var("POSTGRES_USER", "yamong");
            std::string password = get_env_var("POSTGRES_PASSWORD", "yamong");

            std::stringstream conn_string;
            conn_string << "dbname=" << dbname << " "
                       << "host=" << host << " "
                       << "port=" << port << " "
                       << "user=" << user << " "
                       << "password=" << password;

            conn = std::make_unique<pqxx::connection>(conn_string.str());
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Database reconnection failed: " + std::string(e.what()));
    }
}

void DBConnection::insert_events(const std::vector<db_event_t>& events) {    
    // if (events.empty()) return;

    // try {
    //     pqxx::work txn(*conn);
        
    //     // stream_to 사용법 변경
    //     std::vector<std::string> columns = {
    //         "timestamp", "pid", "tid", "syscall_id", "ret", 
    //         "arg1", "arg2", "arg3"
    //     };
        
    //     pqxx::stream_to stream{txn, "syscall_events", columns.begin(), columns.end()};
        
    //     for (const auto& event : events) {
    //         stream.write_values(
    //             event.task.timestamp,
    //             event.task.cgroup_id,
    //             event.task.pid,
    //             event.task.tid,
    //             event.event_id,
    //             event.ret,
    //             event.arg_s32[0],
    //             event.arg_s32[1],
    //             event.arg_s32[2]
    //         );
    //     }

    //     stream.complete();
    //     txn.commit();
    // } catch (const std::exception& e) {
    //     throw std::runtime_error("Failed to insert events: " + std::string(e.what()));
    // }
}