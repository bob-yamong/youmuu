#include "buffer.h"

// 생성자
EventBuffer::EventBuffer(size_t flush_interval_ms) 
    : current_buffer(0)
    , should_stop(false)
    , flush_interval(std::chrono::milliseconds(flush_interval_ms))
    , total_pending_events(0) {
    
    // 플러시 스레드 시작
    flush_threads.emplace_back(&EventBuffer::flush_routine, this);
}

// 소멸자
EventBuffer::~EventBuffer() {
    stop();
    
    for (auto& thread : flush_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

// 이벤트를 버퍼에 추가하는 함수
void EventBuffer::add_event(const event_t& event) {
    // true일 때 버퍼가 중지된 상태 이므로 예외 발생
    if (should_stop) {
        throw std::runtime_error("EventBuffer is stopped");
    }

    // 쓰기 가능한 버퍼를 가져옴
    Buffer* buffer = get_write_buffer();
    // 버퍼가 없을 경우 처리
    if (!buffer) {
        handle_buffer_full();
        buffer = get_write_buffer();  // 재시도
    }

    // mutex lock 사용, 한 버퍼에 한 쓰레드만 접근 가능
    {
        std::lock_guard<std::mutex> lock(buffer_mutex);
        // 버퍼에 이벤트 추가
        buffer->events.push_back(event);
        // 마지막 업데이트 시간
        buffer->last_update = std::chrono::steady_clock::now();
        // 대기 중인 이벤트 수 증가
        total_pending_events++;
        
        // 버퍼가 가득 찼을 때 상태 변경
        if (buffer->events.size() >= MAX_EVENTS) {
            buffer->state.store(BufferState::FULL);
            buffer_cv.notify_one(); // 대기 중인 flush 쓰레드 깨움
        }
    }
}

// 엔진이 종료될 대 버퍼 정리
void EventBuffer::stop() {
    should_stop = true;
    buffer_cv.notify_all();
    
    // 남은 이벤트들 처리
    for (auto& buffer : buffers) {
        if (!buffer.events.empty() && 
            buffer.state.load() != BufferState::PROCESSING) {
            flush_to_db(buffer.events);
        }
    }
}

// 현재 쓰기 가능한 버퍼를 가져오는 함수
EventBuffer::Buffer* EventBuffer::get_write_buffer() {
    // 현재 사용 중인 버퍼 인덱스 가져오기
    size_t current = current_buffer.load();
    // 모든 버퍼를 순차적으로 확인
    for (size_t i = 0; i < BUFFER_COUNT; i++) {
        size_t idx = (current + i) % BUFFER_COUNT;
        auto state = buffers[idx].state.load();
        // READY 상태의 버퍼를 찾으면 return 
        if (state == BufferState::READY) {
            return &buffers[idx];
        }
    }
    return nullptr;
}

// 백그라운드에서 버퍼의 데이터를 DB에 기록하는 함수
void EventBuffer::flush_routine() {
    // stop이 호출될 때까지 무한 루프
    while (!should_stop) {
        std::unique_lock<std::mutex> lock(buffer_mutex);
        
        auto now = std::chrono::steady_clock::now();
        bool should_flush = false;
        
        // 버퍼가 가득차거나, 일정 시간이 지났을 때 flush
        for (auto& buffer : buffers) {
            if (buffer.state.load() == BufferState::FULL ||
                (now - buffer.last_update) >= flush_interval) {
                should_flush = true;
                break;
            }
        }
        
        if (!should_flush) {
            buffer_cv.wait_for(lock, flush_interval);
            continue;
        }
        
        // flush 대상 버퍼 찾기
        for (auto& buffer : buffers) {
            // 버퍼가 비어있지 않고, 처리 중이 아닐 때 flush
            if (!buffer.events.empty() && 
                buffer.state.load() != BufferState::PROCESSING) {
                buffer.state.store(BufferState::PROCESSING);
                // 버퍼 복사 후 비우기 시작
                std::vector<event_t> events_copy = buffer.events;
                lock.unlock();
                
                // flush 성공 시
                if (flush_to_db(events_copy)) {
                    std::lock_guard<std::mutex> lock(buffer_mutex);
                    // 버퍼 비우기
                    buffer.events.clear();
                    total_pending_events -= events_copy.size();
                    buffer.state.store(BufferState::READY);
                }
                
                break;
            }
        }
    }
}

bool EventBuffer::flush_to_db(const std::vector<event_t>& events, size_t retry_count) {
    try {
        db_conn.insert_events(events);
        return true;
    } catch (const std::exception& e) {
        if (retry_count < MAX_RETRY_COUNT) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (retry_count + 1)));
            return flush_to_db(events, retry_count + 1);
        }
        std::cerr << "Failed to flush events after " << MAX_RETRY_COUNT 
                  << " retries: " << e.what() << std::endl;
        return false;
    }
}

// 버퍼안의 이벤트 count
size_t EventBuffer::get_pending_events() const {
    return total_pending_events.load();
}

// 버퍼가 가득 찼을 때 호출되는 함수
void EventBuffer::handle_buffer_full() {
    std::unique_lock<std::mutex> lock(buffer_mutex);
    buffer_cv.notify_one();
    buffer_cv.wait(lock, [this]() {
        return std::any_of(buffers.begin(), buffers.end(),
            [](const Buffer& b) { return b.state.load() == BufferState::READY; });
    });
}