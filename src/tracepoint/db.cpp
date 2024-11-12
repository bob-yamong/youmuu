#include "db.h"

DBConnection::DBConnection() {
    try {
        // TCP/IP 연결을 위한 연결 문자열 구성
        std::stringstream conn_string;
        conn_string << "postgresql://"
                   << env::user << ":"
                   << env::password << "@"
                   << env::host << ":"
                   << env::port << "/"
                   << env::dbname
                   << "?connect_timeout=10"; // 타임아웃 추가

        std::cout << "Attempting to connect to database..." << std::endl;
        conn = std::make_unique<pqxx::connection>(conn_string.str());
        
        // 초기 설정
        pqxx::work w(*conn);
        w.exec("SET synchronous_commit TO OFF");
        w.exec("SET client_encoding TO 'UTF8'");
        w.commit();
        
        std::cout << "Database connection successful! Connected to " << env::dbname 
                  << " at " << env::host << ":" << env::port << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Connection string debug: " << conn_string.str() << std::endl;
        throw std::runtime_error("Database connection failed: " + std::string(e.what()));
    }
}

void DBConnection::ensure_connection() {
    try {
        if (!conn || !conn->is_open()) {
        std::stringstream conn_string;
        conn_string << "postgresql://"
                   << env::user << ":"
                   << env::password << "@"
                   << env::host << ":"
                   << env::port << "/"
                   << env::dbname
                   << "?connect_timeout=10"; // 타임아웃 추가

        std::cout << "Attempting to connect to database..." << std::endl;
        conn = std::make_unique<pqxx::connection>(conn_string.str());
            std::cout << "Database connection successful! Connected to " << env::dbname << " at " << env::host << ":" << env::port << std::endl;
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Database reconnection failed: " + std::string(e.what()));
    }
}

void DBConnection::insert_events(const std::vector<db_event_t>& events) {    
    if (events.empty()) return;

    try {
        pqxx::work txn(*conn);

        auto stream = pqxx::stream_to::table(txn, {"ContainerLog"sv}, {
            "systemcall"sv,
            "enter_or_exit"sv,
            "container_name"sv,
            "pid"sv,
            "ppid"sv,
            "tid"sv,
            "uid"sv,
            "gid"sv,
            "command"sv,
            "atr_0"sv,
            "atr_1"sv,
            "atr_2"sv,
            "atr_3"sv,
            "atr_4"sv,
            "atr_5"sv,
            "return_value"sv,
            "additional_info"sv,
            "called_at"sv,
            "mnt_namespace"sv,
            "pid_namespace"sv,
        });

        for (const auto& event : events) {
            auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                event.timestamp.time_since_epoch()
            ).count();
            
            auto seconds = microseconds / 1000000;
            auto remainingMicros = microseconds % 1000000;
            
            // PostgreSQL timestamp 문자열 생성
            std::time_t time = seconds;
            std::tm* tm = std::gmtime(&time);
            char date_str[32];
            std::strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm);
            
            std::stringstream timestamp_str;
            timestamp_str << date_str << "." << std::setfill('0') << std::setw(6) << remainingMicros;

            stream.write_values(
                event.syscall,
                event.is_enter,
                event.container_name,
                event.pid,
                event.ppid,
                event.tid,
                event.uid,
                event.gid,
                event.comm,
                event.arg0,
                event.arg1,
                event.arg2,
                event.arg3,
                event.arg4,
                event.arg5,
                event.ret,
                event.additional_info,
                timestamp_str.str(),
                event.mnt_namespace,
                event.pid_namespace 
            );
        }

        stream.complete();
        txn.commit();
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to insert events: " + std::string(e.what()));
    }
}