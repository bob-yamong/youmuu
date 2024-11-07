#pragma once

#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <array>
#include "struct.h"
#include "db.h"

class EventBuffer {
public:
    EventBuffer();
    ~EventBuffer();
    
    // 복사 생성자와 대입 연산자 삭제 -> 다중 쓰레드 환경에서 예기치 못한 에러 방지
    EventBuffer(const EventBuffer&) = delete;
    EventBuffer& operator=(const EventBuffer&) = delete;

    // 정보를 버퍼에 추가하는 함수
    void add_event(const event_t& event, const char* task_info);
    // EventBuffer 정지하고 DB에 남은 이벤트들을 모두 삽입하는 함수(일정시간이 지나거나 버퍼가 가득 찼을 때 호출)
    void stop();

private:
    static const size_t MAX_EVENTS = 100000;
    static const size_t BUFFER_COUNT = 4;

    // 버퍼에 이벤트 목록을 저장하는 구조체
    struct Buffer {
        // event_t 구조체를 저장하는 벡터
        std::vector<event_t> events;
        // 현재 DB에 저장 중인지 여부
        bool is_processing;
        // 생성자에서 벡터 사이즈를 미리 할당
        Buffer() : is_processing(false) {
            events.reserve(MAX_EVENTS);
        }
    };

    // 버퍼 객체를 담고 있는 배열 (현재 4개의 버퍼를 사용)
    std::array<Buffer, BUFFER_COUNT> buffers;
    // 현재 사용 중인 버퍼 인덱스
    size_t current_buffer;
    std::mutex buffer_mutex;
    // 일정시간이 지나거나 버퍼가 꽉찼을 때 flush 쓰레드를 깨움
    std::condition_variable buffer_cv;
    // stop() 호출 시 true로 flush 쓰레드 종료
    bool should_stop;
    // 이벤트 정보를 DB에 flush 하는 쓰레드
    std::thread flush_thread;
    DBConnection db_conn;

    // 현재 기록가능한 버퍼 return 
    Buffer* get_write_buffer();
    // 버퍼를 DB에 flush하는 함수, flush thread에서 실행되고 should stop이 true일 때 종료
    void flush_routine();
    // DB에 이벤트 정보를 삽입하는 함수
    void flush_to_db(const std::vector<event_t>& events);
};