#include "EventLogger.h"

EventLogger::EventLogger(size_t bufferSize)
    : bufferSize_(bufferSize),
      buffer1_(),
      buffer2_(),
      buffer3_(),
      buffer4_(),
      currentBuffer_(&buffer1_),
      flushBuffers_(),
      isFlushing_(false),
      shutdown_(false)
{
    // 버퍼 예약
    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    buffer3_.reserve(bufferSize_);
    buffer4_.reserve(bufferSize_);

    // 초기 버퍼 활성화 시간 설정
    current_buffer_time_ = std::chrono::steady_clock::now();

    // syslog 초기화
    openlog("EventLogger", LOG_PID | LOG_CONS, LOG_USER);

    // 플러시 쓰레드 시작
    flushThread_ = std::thread(&EventLogger::flushThreadFunc, this);
}

EventLogger::~EventLogger() {
    // 종료 플래그 설정
    shutdown_.store(true);
    cv_.notify_all();

    if (flushThread_.joinable()) {
        flushThread_.join();
    }

    // 모든 버퍼 플러시
    std::lock_guard<std::mutex> lock(mtx_);

    // 현재 버퍼가 비어있지 않다면 플러시 버퍼 대기열에 추가
    if (!currentBuffer_->empty()) {
        flushBuffers_.push_back(currentBuffer_);
    }

    // 모든 플러시 버퍼 플러시
    while(!flushBuffers_.empty()) {
        std::vector<db_event_t>* bufferToFlush = flushBuffers_.front();
        flushBuffers_.pop_front();
        sendEventsAsCEF(*bufferToFlush);
        bufferToFlush->clear();
    }

    // syslog 종료
    closelog();
}

void EventLogger::addEvent(const db_event_t& e) {
    std::unique_lock<std::mutex> lock(mtx_);
    currentBuffer_->push_back(e);

    if (currentBuffer_->size() >= bufferSize_) {
        // 현재 버퍼를 플러시 버퍼 대기열에 추가
        flushBuffers_.push_back(currentBuffer_);

        // 다음 사용 가능한 버퍼를 찾음
        if (&buffer1_ != currentBuffer_ && buffer1_.size() < bufferSize_) {
            currentBuffer_ = &buffer1_;
        }
        else if (&buffer2_ != currentBuffer_ && buffer2_.size() < bufferSize_) {
            currentBuffer_ = &buffer2_;
        }
        else if (&buffer3_ != currentBuffer_ && buffer3_.size() < bufferSize_) {
            currentBuffer_ = &buffer3_;
        }
        else if (&buffer4_ != currentBuffer_ && buffer4_.size() < bufferSize_) {
            currentBuffer_ = &buffer4_;
        }
        else {
            // 모든 버퍼가 꽉 찼다면, 대기
            cv_.wait(lock, [this]() { return !flushBuffers_.empty(); });
            // 재시도
            if (&buffer1_ != currentBuffer_ && buffer1_.size() < bufferSize_) {
                currentBuffer_ = &buffer1_;
            }
            else if (&buffer2_ != currentBuffer_ && buffer2_.size() < bufferSize_) {
                currentBuffer_ = &buffer2_;
            }
            else if (&buffer3_ != currentBuffer_ && buffer3_.size() < bufferSize_) {
                currentBuffer_ = &buffer3_;
            }
            else if (&buffer4_ != currentBuffer_ && buffer4_.size() < bufferSize_) {
                currentBuffer_ = &buffer4_;
            }
            else {
                // 여전히 모든 버퍼가 꽉 찬 경우, 에러 메시지 출력
                std::cerr << "Error: All buffers are full. Dropping event." << std::endl;
                return;
            }
        }

        // 플러시 플래그 설정
        isFlushing_.store(true);
        cv_.notify_one();

        // current_buffer_time_ 업데이트
        current_buffer_time_ = std::chrono::steady_clock::now();
    }
}

void EventLogger::flushThreadFunc() {
    try {
        while (!shutdown_.load()) {
            std::unique_lock<std::mutex> lock(mtx_);

            // 대기 시간 1초로 설정하여 주기적으로 타임아웃을 체크
            if (cv_.wait_for(lock, std::chrono::seconds(1), [this]() { return !flushBuffers_.empty() || shutdown_.load(); })) {
                // 신호가 들어오거나 shutdown이 설정된 경우
                if (shutdown_.load() && flushBuffers_.empty()) {
                    break;
                }

                while (!flushBuffers_.empty()) {
                    // 플러시할 버퍼를 가져옴
                    std::vector<db_event_t>* bufferToFlush = flushBuffers_.front();
                    flushBuffers_.pop_front();

                    // 플러시 플래그 해제 (대기열이 비었을 때)
                    if(flushBuffers_.empty()) {
                        isFlushing_.store(false);
                    }

                    // 잠금 해제
                    lock.unlock();

                    // 로그 플러시 시작 로그
                    std::cerr << "Flushing buffer..." << std::endl;

                    // CEF 포맷으로 변환하여 syslog에 전송
                    sendEventsAsCEF(*bufferToFlush);

                    // 버퍼 클리어
                    bufferToFlush->clear();

                    // 로그 플러시 완료 로그
                    std::cerr << "Buffer flushed." << std::endl;

                    // 잠금 재획득
                    lock.lock();
                }
            }

            // 타임아웃 체크: 10초 이상 지난 currentBuffer_이 있는지 확인
            auto now = std::chrono::steady_clock::now();

            if (std::chrono::duration_cast<std::chrono::seconds>(now - current_buffer_time_) >= FLUSH_TIMEOUT && !currentBuffer_->empty()) {
                // currentBuffer_를 플러시 대기열에 추가
                flushBuffers_.push_back(currentBuffer_);
                isFlushing_.store(true);
                cv_.notify_one();

                // 플러시 로그
                std::cerr << "Timeout reached for currentBuffer_. Flushing buffer." << std::endl;

                // 다음 사용 가능한 버퍼를 찾음
                if (&buffer1_ != currentBuffer_ && buffer1_.size() < bufferSize_) {
                    currentBuffer_ = &buffer1_;
                }
                else if (&buffer2_ != currentBuffer_ && buffer2_.size() < bufferSize_) {
                    currentBuffer_ = &buffer2_;
                }
                else if (&buffer3_ != currentBuffer_ && buffer3_.size() < bufferSize_) {
                    currentBuffer_ = &buffer3_;
                }
                else if (&buffer4_ != currentBuffer_ && buffer4_.size() < bufferSize_) {
                    currentBuffer_ = &buffer4_;
                }
                else {
                    // 모든 버퍼가 꽉 찼다면, 현재 버퍼를 플러시 대기열에 추가할 수 없음
                    std::cerr << "Error: All buffers are full. Dropping buffer due to timeout." << std::endl;
                }

                // current_buffer_time_ 업데이트
                current_buffer_time_ = std::chrono::steady_clock::now();
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in flushThreadFunc: " << ex.what() << "\n";
    }
    catch (...) {
        std::cerr << "Unknown exception in flushThreadFunc\n";
    }
}

void EventLogger::sendEventsAsCEF(const std::vector<db_event_t>& events) {
    if (events.empty()) return;

    for (const auto& event : events) {
        // CEF 기본 필드 설정
        std::stringstream cef;
        cef << "CEF:0|Container|Yamong_TP|1.0|"
            << event.syscall << "|"
            << (event.is_enter ? "Syscall Enter" : "Syscall Exit") << "|"
            << "5|" // Severity 예시: 중간 수준
            << "src=" << event.container_name << " "
            << "pid=" << event.pid << " "
            << "ppid=" << event.ppid << " "
            << "tid=" << event.tid << " "
            << "uid=" << event.uid << " "
            << "gid=" << event.gid << " "
            << "comm=" << event.comm << " "
            << "arg0=" << event.arg0 << " "
            << "arg1=" << event.arg1 << " "
            << "arg2=" << event.arg2 << " "
            << "arg3=" << event.arg3 << " "
            << "arg4=" << event.arg4 << " "
            << "arg5=" << event.arg5 << " "
            << "ret=" << event.ret << " "
            << "additional_info=" << event.additional_info << " "
            << "timestamp=";

        // 타임스탬프 포맷팅 (ISO 8601 형식)
        auto time = std::chrono::system_clock::to_time_t(event.timestamp);
        std::tm tm = *std::gmtime(&time);
        char time_buffer[64];
        std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%dT%H:%M:%S", &tm);
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            event.timestamp.time_since_epoch()
        ).count() % 1000000;
        cef << time_buffer << "." << std::setfill('0') << std::setw(6) << microseconds;

        // syslog에 CEF 로그 전송
        syslog(LOG_INFO, "%s", cef.str().c_str());
    }
}

