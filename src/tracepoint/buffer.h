#pragma once

#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <array>
#include <chrono>
#include <atomic>
#include "struct.h"
#include "db.h"

class EventBuffer {
public:
    explicit EventBuffer(size_t flush_interval_ms = 5000);
    ~EventBuffer();
    
    // 복사 생성자와 대입 연산자 삭제 -> 다중 쓰레드 환경에서 예기치 못한 에러 방지
    EventBuffer(const EventBuffer&) = delete;
    EventBuffer& operator=(const EventBuffer&) = delete;
    // 이동 생성자와 대입 연산자도 명시적으로 삭제
    EventBuffer(EventBuffer&&) = delete;
    EventBuffer& operator=(EventBuffer&&) = delete;

    // 정보를 버퍼에 추가하는 함수
    void add_event(const event_t& event);
    // EventBuffer 정지하는 함수
    void stop();
    // 현재 버퍼 상태 확인
    size_t get_pending_events() const;
    bool is_running() const { return !should_stop; }

private:
    static const size_t MAX_EVENTS = 100000;
    static const size_t BUFFER_COUNT = 4;
    static constexpr size_t MAX_RETRY_COUNT = 3;

    enum class BufferState {
        READY,          // 쓰기 가능
        PROCESSING,     // DB에 쓰는 중
        FULL           // 가득 참
    };

    // 버퍼 구조체
    struct Buffer {
        std::vector<event_t> events;
        std::atomic<BufferState> state;
        std::chrono::steady_clock::time_point last_update;

        Buffer() : state(BufferState::READY) {
            events.reserve(MAX_EVENTS);
        }
    };

    // 멤버 변수
    std::array<Buffer, BUFFER_COUNT> buffers;// 버퍼 객체를 담고 있는 배열 (현재 4개의 버퍼를 사용)
    std::atomic<size_t> current_buffer; // 현재 사용 중인 버퍼 인덱스
    mutable std::mutex buffer_mutex;
    std::condition_variable buffer_cv;  // 일정시간이 지나거나 버퍼가 꽉찼을 때 flush 쓰레드를 깨움
    std::atomic<bool> should_stop;  // stop() 호출 시 true로 flush 쓰레드 종료
    std::vector<std::thread> flush_threads; // 이벤트 정보를 DB에 flush 하는 쓰레드
    DBConnection db_conn;
    const std::chrono::milliseconds flush_interval; // flush 간격
    std::atomic<size_t> total_pending_events;    // 현재 버퍼에 대기 중인 이벤트 수

    // 내부 헬퍼 메서드
    Buffer* get_write_buffer(); // 현재 기록가능한 버퍼 return 
    void flush_routine();   // 버퍼를 DB에 flush하는 함수, flush thread에서 실행되고 should stop이 true일 때 종료
    bool flush_to_db(const std::vector<event_t>& events, size_t retry_count = 0);   // DB에 이벤트 정보를 삽입하는 함수
    void rotate_buffer();   // 버퍼를 교체하는 함수
    bool should_flush(const Buffer& buffer) const;  // 버퍼를 flush해야 하는지 확인하는 함수
    void handle_buffer_full();  // 버퍼가 가득 찼을 때 처리하는 함수
};