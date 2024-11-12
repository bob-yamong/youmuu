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
        std::string dbname = get_env_var("POSTGRES_DB", "yamong_postgres");
        std::string user = get_env_var("POSTGRES_USER", "temp_admin");
        std::string password = get_env_var("POSTGRES_PASSWORD", "temp_password");

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
        std::cout << "Database connection successful! Connected to " << dbname << " at " << host << ":" << port << std::endl;

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
            std::string dbname = get_env_var("POSTGRES_DB", "yamong_postgres");
            std::string user = get_env_var("POSTGRES_USER", "temp_admin");
            std::string password = get_env_var("POSTGRES_PASSWORD", "temp_password");

            std::stringstream conn_string;
            conn_string << "dbname=" << dbname << " "
                       << "host=" << host << " "
                       << "port=" << port << " "
                       << "user=" << user << " "
                       << "password=" << password;

            conn = std::make_unique<pqxx::connection>(conn_string.str());
            std::cout << "Database connection successful! Connected to " << dbname << " at " << host << ":" << port << std::endl;
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

// void EventLogger::insertEventsToDB(const std::vector<event>& buffer) {
//     if (buffer.empty()) return;

//     try {
//         pqxx::work txn(dbConnection_);
//         auto stream = pqxx::stream_to::table(txn, {"ContainerLog"sv}, {
//             "systemcall",
//             "container_name",
//             "pid",
//             "ppid",
//             "tid",
//             "uid",
//             "gid",
//             "command",
//             "atr_0",
//             "atr_1",
//             "atr_2",
//             "atr_3",
//             "atr_4",
//             "atr_5"
//         });

//         // 개선된 문자열 정제 함수
//         auto sanitizeString = [](const char* str) -> std::string {
//             std::string result;
//             const unsigned char* p = reinterpret_cast<const unsigned char*>(str);
            
//             while (*p && result.length() < MAX_ARG_LEN) {
//                 // UTF-8 유효성 검사 및 필터링
//                 if (*p < 0x80) { // ASCII 문자
//                     if (*p >= 0x20 && *p != 0x7F) { // 출력 가능한 ASCII
//                         result += static_cast<char>(*p);
//                     }
//                     p++;
//                 } else if ((*p & 0xE0) == 0xC0) { // 2바이트 UTF-8
//                     if (p[1] && (p[1] & 0xC0) == 0x80) {
//                         result += static_cast<char>(p[0]);
//                         result += static_cast<char>(p[1]);
//                         p += 2;
//                     } else {
//                         p++;
//                     }
//                 } else if ((*p & 0xF0) == 0xE0) { // 3바이트 UTF-8
//                     if (p[1] && p[2] && 
//                         (p[1] & 0xC0) == 0x80 && 
//                         (p[2] & 0xC0) == 0x80) {
//                         result += static_cast<char>(p[0]);
//                         result += static_cast<char>(p[1]);
//                         result += static_cast<char>(p[2]);
//                         p += 3;
//                     } else {
//                         p++;
//                     }
//                 } else {
//                     p++; // 유효하지 않은 바이트는 건너뛰기
//                 }
//             }
//             return result;
//         };

//         for (const auto& e : buffer) {
//             std::string container_name;
//             for (const auto& container : ContainerManager::containers) {
//                 if (container.cgroup_id == e.cgroup_id) {
//                     container_name = container.name;
//                     break;
//                 }
//             }

//             stream.write_values(
//                 sanitizeString(e.syscall),
//                 container_name,
//                 e.pid,
//                 e.ppid,
//                 e.tid,
//                 e.uid,
//                 e.gid,
//                 sanitizeString(e.comm),
//                 sanitizeString(e.argv[0]),
//                 sanitizeString(e.argv[1]),
//                 sanitizeString(e.argv[2]),
//                 sanitizeString(e.argv[3]),
//                 sanitizeString(e.argv[4]),
//                 sanitizeString(e.argv[5])
//             );
//         }
//         stream.complete();
//         txn.commit();
//     }
//     catch (const pqxx::sql_error &e) {
//         std::cerr << "SQL error: " << e.what() << "\n";
//         std::cerr << "Query was: " << e.query() << "\n";
//     }
//     catch (const std::exception &e) {
//         std::cerr << "Exception in insertEventsToDB: " << e.what() << "\n";
//     }
// }