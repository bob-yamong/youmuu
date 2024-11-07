#pragma once

#include <string>
#include <vector>
#include <pqxx/pqxx>
#include "struct.h"

class DBConnection {
public:
    DBConnection();
    ~DBConnection();

    // event_t를 DB에 삽입하는 함수, 이벤트 목록을 batch insert 쿼리로 생성하여 삽입
    void insert_events(const std::vector<event_t>& events);

private:
    // DB 연결 객체
    std::unique_ptr<pqxx::connection> conn;
    // DB 연결을 확인하고 없으면 연결하는 함수
    void ensure_connection();
    // insert 쿼리를 생성하는 함수
    std::string create_batch_insert_query(const std::vector<event_t>& events);
};