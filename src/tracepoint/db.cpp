#include <sstream>
#include "db.h"

DBConnection::DBConnection() {
    try {
        // 6.4.5 버전에서는 기본적인 연결 문자열 사용
        conn = std::make_unique<pqxx::connection>(
            "dbname=securitylogs "
            "host=localhost "
            "port=5432 "
            "user=username "
            "password=password"
        );
        
        // 초기 설정
        pqxx::work w(*conn);
        w.exec("SET synchronous_commit TO OFF");
        w.exec("SET client_encoding TO 'UTF8'");
        w.commit();
    } catch (const std::exception& e) {
        throw std::runtime_error("Database connection failed: " + std::string(e.what()));
    }
}

DBConnection::~DBConnection() {
    try {
        if (conn && conn->is_open()) {
            conn->disconnect();
        }
    } catch (...) {
        // 소멸자에서는 예외를 무시
    }
}

void DBConnection::ensure_connection() {
    try {
        if (!conn || !conn->is_open()) {
            conn = std::make_unique<pqxx::connection>(
                "dbname=securitylogs "
                "host=localhost "
                "port=5432 "
                "user=username "
                "password=password"
            );
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Database reconnection failed: " + std::string(e.what()));
    }
}

void DBConnection::insert_events(const std::vector<event_t>& events) {
    if (events.empty()) return;

    static const int MAX_RETRIES = 3;
    int retry_count = 0;

    while (retry_count < MAX_RETRIES) {
        try {
            ensure_connection();
            
            pqxx::work txn(*conn);
            
            // 메모리 미리 할당
            std::stringstream copy_data;
            
            // 데이터 포맷팅
            for (const auto& event : events) {
                copy_data << event.timestamp << "\t"
                         << event.pid << "\t"
                         << event.tid << "\t"
                         << event.syscall_id << "\t"
                         << event.ret << "\t"
                         << event.arg_s32[0] << "\t"
                         << event.arg_s32[1] << "\t"
                         << event.arg_s32[2] << "\n";
            }

            // COPY 명령어 실행
            std::string copy_sql = 
                "COPY syscall_events (timestamp, pid, tid, syscall_id, ret, arg1, arg2, arg3) "
                "FROM STDIN WITH (FORMAT text)";
                
            txn.exec(copy_sql);
            
            // COPY 데이터 전송
            const std::string& data = copy_data.str();
            conn->putline(data.c_str());
            conn->putline("\\.\n");  // COPY 종료
            
            txn.commit();
            return;  // 성공시 종료

        } catch (const pqxx::broken_connection& e) {
            retry_count++;
            if (retry_count >= MAX_RETRIES) {
                throw std::runtime_error("Database connection lost after max retries: " + std::string(e.what()));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * retry_count));
            conn.reset();
        } catch (const std::exception& e) {
            throw std::runtime_error("Database insert failed: " + std::string(e.what()));
        }
    }
}

std::string DBConnection::create_batch_insert_query(const std::vector<event_t>& events) {
    if (events.empty()) return "";

    std::stringstream query;
    query << "INSERT INTO syscall_events "
          << "(timestamp, pid, tid, syscall_id, ret, arg1, arg2, arg3) VALUES ";
    
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        query << "(" << event.timestamp << ","
              << event.pid << ","
              << event.tid << ","
              << event.syscall_id << ","
              << event.ret << ","
              << event.arg_s32[0] << ","
              << event.arg_s32[1] << ","
              << event.arg_s32[2] << ")";
        
        if (i < events.size() - 1) query << ",";
    }
    
    return query.str();
}