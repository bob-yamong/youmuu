#include "EventLogger.h" 
#include <nlohmann/json.hpp>

// 편의상 네임스페이스 사용
using json = nlohmann::json;

// 생성자
EventLogger::EventLogger(size_t bufferCount, const std::string& brokers, const std::string& topic)
    : buffers_(),
      currentBuffer_(nullptr),
      flushBuffers_(),
      isFlushing_(false),
      shutdown_(false),
      producer_(nullptr),
      topic_str_(topic),
      topic_(nullptr),
      std::unique_ptr<RdKafka::Conf> conf_(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));
        std::unique_ptr<RdKafka::Conf> tconf_(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC));
      stop_(false)
{
    // 버퍼 생성 및 예약
    if (bufferCount == 0) {
        throw std::invalid_argument("bufferCount must be greater than 0");
    }

    buffers_.reserve(bufferCount);
    for (size_t i = 0; i < bufferCount; ++i) {
        buffers_.emplace_back();
        buffers_.back().reserve(bufferSize_);
    }

    // 현재 사용 중인 버퍼 설정
    currentBuffer_ = &buffers_[0];
    current_buffer_time_ = std::chrono::steady_clock::now();

    // Kafka 설정
    std::string errstr;
    if (conf_->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << "Kafka 설정 오류: " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    // 배치 및 압축 처리 설정
    if (conf_->set("queue.buffering.max.messages", "1000000", errstr) != RdKafka::Conf::CONF_OK) { // 1,000,000개
        std::cerr << "Kafka 설정 오류 (queue.buffering.max.messages): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("queue.buffering.max.kbytes", "2097152", errstr) != RdKafka::Conf::CONF_OK) { // 2GB
        std::cerr << "Kafka 설정 오류 (queue.buffering.max.kbytes): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("compression.type", "gzip", errstr) != RdKafka::Conf::CONF_OK) { // gzip 압축 사용
        std::cerr << "Kafka 설정 오류 (compression.type): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("batch.size", "327680", errstr) != RdKafka::Conf::CONF_OK) { // 320KB
        std::cerr << "Kafka 설정 오류 (batch.size): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("linger.ms", "500", errstr) != RdKafka::Conf::CONF_OK) { // 0.5초
        std::cerr << "Kafka 설정 오류 (linger.ms): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("acks", "1", errstr) != RdKafka::Conf::CONF_OK) { // 리더에게만 확인 받음
        std::cerr << "Kafka 설정 오류 (acks): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("retries", "3", errstr) != RdKafka::Conf::CONF_OK) { // 재시도 횟수
        std::cerr << "Kafka 설정 오류 (retries): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("retry.backoff.ms", "100", errstr) != RdKafka::Conf::CONF_OK) { // 재시도 간격
        std::cerr << "Kafka 설정 오류 (retry.backoff.ms): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    // 프로듀서 생성
    producer_ = RdKafka::Producer::create(conf_, errstr);
    if (!producer_) {
        std::cerr << "Kafka 프로듀서 생성 실패: " << errstr << std::endl;
        throw std::runtime_error("Kafka 프로듀서 생성 실패");
    }

    // 토픽 설정
    topic_ = RdKafka::Topic::create(producer_, topic_str_, tconf_, errstr);
    if (!topic_) {
        std::cerr << "Kafka 토픽 생성 실패: " << errstr << std::endl;
        throw std::runtime_error("Kafka 토픽 생성 실패");
    }

    delete conf_;
    delete tconf_;

    // 쓰레드풀 초기화 (CPU 코어 수 기준)
    size_t numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4; // 기본값 설정
    for (size_t i = 0; i < numThreads; ++i) {
        threadPool_.emplace_back(&EventLogger::threadPoolWorker, this);
    }

    // 플러시 쓰레드 시작
    flushThread_ = std::thread(&EventLogger::flushThreadFunc, this);

    initJsonTemplate();
}

// 소멸자
EventLogger::~EventLogger() {
    // 종료 플래그 설정
    shutdown_.store(true);
    cv_.notify_all();

    if (flushThread_.joinable()) {
        flushThread_.join();
    }

    // 쓰레드풀 종료
    {
        std::unique_lock<std::mutex> lock(threadPoolMutex_);
        stop_ = true;
        threadPoolCV_.notify_all();
    }

    for (auto& thread : threadPool_) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    // 모든 버퍼 플러시
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto& buffer : buffers_) {
            if (!buffer.empty()) {
                flushBuffers_.push_back(&buffer);
            }
        }
    }

    while (!flushBuffers_.empty()) {
        std::vector<db_event_t>* bufferToFlush = flushBuffers_.front();
        flushBuffers_.pop_front();
        sendEventsToKafka(*bufferToFlush);
        bufferToFlush->clear();
    }

    // Kafka 프로듀서 정리
    if (producer_) {
        producer_->flush(10000); // 최대 10초 동안 메시지 전송 시도
        delete producer_;
    }

    if (topic_) {
        delete topic_;
    }
}

// 로그 이벤트 추가
void EventLogger::addEvent(const db_event_t& e) {
    std::unique_lock<std::mutex> lock(mtx_);
    currentBuffer_->push_back(e);

    if (currentBuffer_->size() >= bufferSize_) {
        // 현재 버퍼를 플러시 버퍼 대기열에 추가
        flushBuffers_.push_back(currentBuffer_);

        // 다음 사용 가능한 버퍼을 찾음
        bool found = false;
        for (auto& buffer : buffers_) {
            if (&buffer != currentBuffer_ && buffer.size() < bufferSize_) {
                currentBuffer_ = &buffer;
                found = true;
                break;
            }
        }

        if (!found) {
            // 모든 버퍼가 꽉 찼다면, 대기
            cv_.wait(lock, [this]() { return !flushBuffers_.empty(); });
            // 재시도
            for (auto& buffer : buffers_) {
                if (&buffer != currentBuffer_ && buffer.size() < bufferSize_) {
                    currentBuffer_ = &buffer;
                    found = true;
                    break;
                }
            }
            if (!found) {
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

void EventLogger::flushThreadFunc()
{
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

                    // 카프카 전송 
                    sendEventsToKafka(*bufferToFlush);

                    // 버퍼 클리어
                    bufferToFlush->clear();

                    // 로그 플러시 완료 로그
                    std::cerr << "Buffer flushed." << std::endl;

                    // 잠금 재획득
                    lock.lock();
                }
            }

            // 타임아웃 체크: 5초 이상 지난 currentBuffer_이 있는지 확인
            auto now = std::chrono::steady_clock::now();

            if (std::chrono::duration_cast<std::chrono::seconds>(now - current_buffer_time_) >= FLUSH_TIMEOUT && !currentBuffer_->empty()) {
                // currentBuffer_를 플러시 대기열에 추가
                flushBuffers_.push_back(currentBuffer_);
                isFlushing_.store(true);
                cv_.notify_one();

                // 플러시 로그
                std::cerr << "Timeout reached for currentBuffer_. Flushing buffer." << std::endl;

                // 다음 사용 가능한 버퍼을 찾음
                bool found = false;
                for (auto& buffer : buffers_) {
                    if (&buffer != currentBuffer_ && buffer.size() < bufferSize_) {
                        currentBuffer_ = &buffer;
                        found = true;
                        break;
                    }
                }

                if (!found) {
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

// 쓰레드풀 워커 함수
void EventLogger::threadPoolWorker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(threadPoolMutex_);
            threadPoolCV_.wait(lock, [this]() { return stop_ || !tasks_.empty(); });

            if (stop_ && tasks_.empty()) {
                return;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
        }
        task();
    }
}

// 작업 큐에 작업 추가
void EventLogger::enqueueTask(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(threadPoolMutex_);
        tasks_.emplace(task);
    }
    threadPoolCV_.notify_one();
}

// Kafka에 이벤트 비동기 전송 (배치 처리)
void EventLogger::sendEventsToKafka(const std::vector<db_event_t>& events) {
    if (events.empty()) return;

    std::vector<db_event_t> eventsCopy = events;
    
    enqueueTask([this, eventsCopy]() {
        auto start = std::chrono::steady_clock::now();
        size_t messageCount = 0;
        
        // 배치 설정
        const size_t max_batch_size = 1 * 1024 * 1024; // 1MB
        std::vector<std::string> batch;
        size_t current_batch_size = 0;

        for (const auto& event_item : eventsCopy) {
            std::string message = serializeEvent(event_item);
            
            // 메시지가 비어있지 않은 경우에만 처리
            if (!message.empty()) {
                batch.push_back(message);
                current_batch_size += message.size();

                // 배치 크기 초과 시 전송
                if (current_batch_size >= max_batch_size) {
                    sendBatchToKafka(batch);
                    messageCount += batch.size();
                    batch.clear();
                    current_batch_size = 0;
                }
            }
        }

        // 남은 메시지 전송
        if (!batch.empty()) {
            sendBatchToKafka(batch);
            messageCount += batch.size();
        }

        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "Sent " << messageCount << " messages to Kafka in " << duration << " ms." << std::endl;
    });
}

// Kafka에 배치 전송
void EventLogger::sendBatchToKafka(const std::vector<std::string>& batch) {
    const int POLL_INTERVAL = 100;  // 100개 메시지마다 poll
    for (size_t i = 0; i < batch.size(); ++i) {
        // ... produce 로직 ...
        if (i % POLL_INTERVAL == 0) {
            producer_->poll(0);
        }
    }
    producer_->poll(0);  // 마지막 poll
}

// 문자열 필터링을 위한 유틸리티 함수
std::string EventLogger::sanitizeString(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    
    for (unsigned char c : input) {
        // 출력 가능한 ASCII 문자만 허용 (32-126 범위)
        // 또는 UTF-8 멀티바이트 문자의 시작 부분
        if ((c >= 32 && c <= 126) || (c >= 192 && c <= 247)) {
            output += c;
        } else {
            output += '.'; // 잘못된 문자는 점으로 대체
        }
    }
    return output;
}

// JSON 템플릿 초기화 함수
void EventLogger::initJsonTemplate() {
    json_template_ = {
        {"timestamp", 0},
        {"container_name", ""},
        {"syscall", ""},
        {"is_enter", false},
        {"pid_namespace", 0},
        {"mnt_namespace", 0},
        {"ppid", 0},
        {"pid", 0},
        {"tid", 0},
        {"uid", 0},
        {"gid", 0},
        {"ret", 0},
        {"comm", ""},
        {"arg0", 0},
        {"arg1", 0},
        {"arg2", 0},
        {"arg3", 0},
        {"arg4", 0},
        {"arg5", 0},
        {"additional_info", ""},
        {"data_type", "db_event"}
    };
}

// 개선된 이벤트 직렬화 함수
std::string EventLogger::serializeEvent(const db_event_t& event_item) {
    try {
        nlohmann::json j = json_template_; // 템플릿 복사

        // 타임스탬프 설정
        j["timestamp"] = std::chrono::duration_cast<std::chrono::microseconds>(
            event_item.timestamp.time_since_epoch()).count();

        // 문자열 필드들은 sanitize 처리
        j["container_name"] = sanitizeString(event_item.container_name);
        j["syscall"] = sanitizeString(event_item.syscall);
        j["comm"] = sanitizeString(event_item.comm);
        j["additional_info"] = sanitizeString(event_item.additional_info);

        // 숫자 필드들은 직접 할당
        j["is_enter"] = event_item.is_enter;
        j["pid_namespace"] = event_item.pid_namespace;
        j["mnt_namespace"] = event_item.mnt_namespace;
        j["ppid"] = event_item.ppid;
        j["pid"] = event_item.pid;
        j["tid"] = event_item.tid;
        j["uid"] = event_item.uid;
        j["gid"] = event_item.gid;
        j["ret"] = event_item.ret;
        
        // 인자값들 설정
        j["arg0"] = event_item.arg0;
        j["arg1"] = event_item.arg1;
        j["arg2"] = event_item.arg2;
        j["arg3"] = event_item.arg3;
        j["arg4"] = event_item.arg4;
        j["arg5"] = event_item.arg5;

        return j.dump();
    } catch (const std::exception& e) {
        std::cerr << "JSON serialization error: " << e.what() << std::endl;
        
        // 에러 발생 시 최소한의 정보만 담은 JSON 반환
        nlohmann::json error_json = {
            {"error", "Serialization failed"},
            {"timestamp", std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()},
            {"pid", event_item.pid},
            {"syscall", sanitizeString(event_item.syscall)}
        };
        return error_json.dump();
    }
}