#pragma once

#include <linux/types.h>
#include <string>
#include <vector>
#include <pqxx/pqxx>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <ctime>
#include <iomanip>
#include "struct.h"
#include "user_struct.h"

using namespace std::string_view_literals;

class DBConnection {
public:
    DBConnection();
    // event_t를 DB에 삽입하는 함수, 이벤트 목록을 batch insert 쿼리로 생성하여 삽입
    // void insert_events(const std::vector<event_t>& events);
    void insert_events(const std::vector<db_event_t>& events);

private:
    // DB 연결 객체
    std::unique_ptr<pqxx::connection> conn;
    // DB 연결을 확인하고 없으면 연결하는 함수
    void ensure_connection();
};