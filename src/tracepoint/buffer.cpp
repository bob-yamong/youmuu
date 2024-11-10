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

void EventBuffer::add_event(const event_t& event) {
    if (should_stop) {
        throw std::runtime_error("EventBuffer is stopped");
    }

    Buffer* buffer = get_write_buffer();
    if (!buffer) {
        handle_buffer_full();
        buffer = get_write_buffer();  // 재시도
    }

    {
        std::lock_guard<std::mutex> lock(buffer_mutex);
        buffer->events.push_back(event);
        buffer->last_update = std::chrono::steady_clock::now();
        total_pending_events++;
        
        if (buffer->events.size() >= MAX_EVENTS) {
            buffer->state.store(BufferState::FULL);
            buffer_cv.notify_one();
        }
    }
}

void EventBuffer::flush_routine() {
    while (!should_stop) {
        std::unique_lock<std::mutex> lock(buffer_mutex);
        
        Buffer* to_flush = nullptr;
        for (auto& buffer : buffers) {
            if (buffer.is_processing && !buffer.events.empty()) {
                to_flush = &buffer;
                break;
            }
        }
        
        if (!to_flush) {
            buffer_cv.wait_for(lock, std::chrono::milliseconds(100));
            continue;
        }
        
        // 여기서 swap을 사용하여 벡터 교체
        std::vector<event_t> events_copy;
        events_copy.swap(to_flush->events);  // 메모리 복사 없이 벡터 교체
        to_flush->is_processing = false;
        
        lock.unlock();
        
        try {
            flush_to_db(events_copy);
        } catch (const std::exception& e) {
            std::cerr << "DB flush error: " << e.what() << std::endl;
            // 에러 발생 시 이벤트 재삽입
            for (const auto& event : events_copy) {
                add_event(event, nullptr);
            }
        }
    }
}

void EventBuffer::add_event(const event_t& event, const char* task_info) {
    std::unique_lock<std::mutex> lock(buffer_mutex);
    
    Buffer* current = get_write_buffer();
    if (!current) {
        // 모든 버퍼가 가득 찼을 때 대기
        buffer_cv.wait(lock, [this]() {
            return get_write_buffer() != nullptr;
        });
        current = get_write_buffer();
    }
    
    current->events.push_back(event);
    
    // 버퍼가 임계치에 도달하면 플러시 트리거
    if (current->events.size() >= MAX_EVENTS * 0.8) {
        current->is_processing = true;
        buffer_cv.notify_one();
    }
}

Buffer* EventBuffer::get_write_buffer() {
    for (size_t i = 0; i < BUFFER_COUNT; i++) {
        size_t idx = (current_buffer + i) % BUFFER_COUNT;
        if (!buffers[idx].is_processing && buffers[idx].events.size() < MAX_EVENTS) {
            current_buffer = idx;
            return &buffers[idx];
        }
    }
    return nullptr;
}

void EventBuffer::stop() {
    should_stop = true;
    buffer_cv.notify_all();
}

void EventBuffer::flush_to_db(const std::vector<event_t>& events) {
    if (!events.empty()) {
        db_conn.insert_events(events);
    }
}