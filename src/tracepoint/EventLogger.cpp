#include "EventLogger.h" 
#include <nlohmann/json.hpp>

// 편의상 네임스페이스 사용
using json = nlohmann::json;

// 생성자
EventLogger::EventLogger(size_t bufferCount, const std::string& brokers, const std::string& topic)
    : currentBuffer_(nullptr),
      isFlushing_(false),
      shutdown_(false),
      producer_(nullptr),
      topic_str_(topic),
      topic_(nullptr),
      conf_(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL)),
      tconf_(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC)),
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

    // availableBuffers_에 모든 버퍼를 추가
    {
        std::lock_guard<std::mutex> lock(availableBuffersMutex_);
        for (auto& buffer : buffers_) {
            availableBuffers_.push_back(&buffer);
        }
    }

    // 현재 사용 중인 버퍼 설정
    {
        std::lock_guard<std::mutex> lock(availableBuffersMutex_);
        if (!availableBuffers_.empty()) {
            currentBuffer_ = availableBuffers_.front();
            availableBuffers_.pop_front();
            current_buffer_time_ = std::chrono::steady_clock::now();
        } else {
            throw std::runtime_error("No available buffers at initialization");
        }
    }
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

    if (conf_->set("batch.size", "10485760", errstr) != RdKafka::Conf::CONF_OK) { // 320KB
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
        std::lock_guard<std::mutex> flushLock(flushBuffersMutex_);
        for (auto& buffer : buffers_) {
            if (!buffer.empty()) {
                flushBuffers_.push_back(&buffer);
            }
        }
    }

    while (true) {
        std::vector<db_event_t>* bufferToFlush = nullptr;
        {
            std::lock_guard<std::mutex> flushLock(flushBuffersMutex_);
            if (flushBuffers_.empty()) break;
            bufferToFlush = flushBuffers_.front();
            flushBuffers_.pop_front();
        }

        // 카프카 전송
        sendEventsToKafka(std::move(*bufferToFlush));

        // 버퍼 클리어
        bufferToFlush->clear();

        // 사용 가능한 버퍼 큐에 반환
        {
            std::lock_guard<std::mutex> availLock(availableBuffersMutex_);
            availableBuffers_.push_back(bufferToFlush);
        }
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
    if (!currentBuffer_) {
        // 사용 가능한 버퍼가 있는지 확인
        {
            std::lock_guard<std::mutex> availLock(availableBuffersMutex_);
            if (availableBuffers_.empty()) {
                // 모든 버퍼가 사용 중이므로 대기
                cv_.wait(lock, [this]() { return !availableBuffers_.empty() || shutdown_.load(); });
                if (shutdown_.load()) return;
            }

            if (!availableBuffers_.empty()) {
                currentBuffer_ = availableBuffers_.front();
                availableBuffers_.pop_front();
                current_buffer_time_ = std::chrono::steady_clock::now();
            } else {
                // 여전히 사용 가능한 버퍼가 없을 경우
                std::cerr << "Error: All buffers are full. Dropping event." << std::endl;
                return;
            }
        }
    }

    currentBuffer_->push_back(e);

    if (currentBuffer_->size() >= bufferSize_) {
        // 현재 버퍼를 플러시 버퍼 대기열에 추가
        {
            std::lock_guard<std::mutex> flushLock(flushBuffersMutex_);
            flushBuffers_.push_back(currentBuffer_);
            isFlushing_.store(true);
        }
        cv_.notify_one();

        // 현재 버퍼를 null로 설정하여 다음 이벤트에서 새로운 버퍼를 할당받도록 함
        currentBuffer_ = nullptr;
    }
}


void EventLogger::flushThreadFunc()
{
    try {
        while (!shutdown_.load()) {
            std::unique_lock<std::mutex> lock(mtx_);

            // 대기 시간 1초로 설정하여 주기적으로 타임아웃을 체크
            if (cv_.wait_for(lock, std::chrono::seconds(1), [this]() { 
                return !flushBuffers_.empty() || shutdown_.load(); 
            })) {
                // 신호가 들어오거나 shutdown이 설정된 경우
                if (shutdown_.load() && flushBuffers_.empty()) {
                    break;
                }

                while (true) {
                    std::vector<db_event_t>* bufferToFlush = nullptr;
                    {
                        std::lock_guard<std::mutex> flushLock(flushBuffersMutex_);
                        if (flushBuffers_.empty()) break;
                        bufferToFlush = flushBuffers_.front();
                        flushBuffers_.pop_front();
                        if (flushBuffers_.empty()) {
                            isFlushing_.store(false);
                        }
                    }

                    // 잠금 해제
                    lock.unlock();

                    // 로그 플러시 시작 로그
                    std::cerr << "Flushing buffer..." << std::endl;

                    // 카프카 전송 
                    sendEventsToKafka(std::move(*bufferToFlush));

                    // 버퍼 클리어
                    bufferToFlush->clear();

                    // 사용 가능한 버퍼 큐에 반환
                    {
                        std::lock_guard<std::mutex> availLock(availableBuffersMutex_);
                        availableBuffers_.push_back(bufferToFlush);
                    }
                    cv_.notify_all(); // 대기 중인 쓰레드에게 알림

                    // 로그 플러시 완료 로그
                    // std::cerr << "Buffer flushed." << std::endl;

                    // 잠금 재획득
                    lock.lock();
                }
            }

            // 타임아웃 체크: 5초 이상 지난 currentBuffer_이 있는지 확인
            auto now = std::chrono::steady_clock::now();

            if (currentBuffer_ && (std::chrono::duration_cast<std::chrono::seconds>(now - current_buffer_time_) >= FLUSH_TIMEOUT) && !currentBuffer_->empty()) {
                // currentBuffer_를 플러시 대기열에 추가
                {
                    std::lock_guard<std::mutex> flushLock(flushBuffersMutex_);
                    flushBuffers_.push_back(currentBuffer_);
                    isFlushing_.store(true);
                }
                cv_.notify_one();

                // 플러시 로그
                std::cerr << "Timeout reached for currentBuffer_. Flushing buffer." << std::endl;

                // 다음 사용 가능한 버퍼을 찾음
                {
                    std::lock_guard<std::mutex> availLock(availableBuffersMutex_);
                    if (!availableBuffers_.empty()) {
                        currentBuffer_ = availableBuffers_.front();
                        availableBuffers_.pop_front();
                        current_buffer_time_ = std::chrono::steady_clock::now();
                    } else {
                        // 모든 버퍼가 꽉 찼다면, 현재 버퍼를 플러시 대기열에 추가할 수 없음
                        std::cerr << "Error: All buffers are full. Dropping buffer due to timeout." << std::endl;
                        // currentBuffer_을 유지하거나 다른 처리를 할 수 있습니다.
                        // 여기서는 플러시 후 currentBuffer_을 null로 설정합니다.
                        currentBuffer_ = nullptr;
                    }
                }
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
void EventLogger::sendEventsToKafka(std::vector<db_event_t>&& events) {
    if (events.empty()) return;

    enqueueTask([this, events = std::move(events)]() mutable {
        auto start = std::chrono::steady_clock::now();
        size_t messageCount = 0;

        // 배치 설정
        const size_t max_batch_size = 10 * 1024 * 1024; // 1MB
        std::vector<std::string> batch;
        batch.reserve(100); // 예시 배치 크기
        size_t current_batch_size = 0;

        for (const auto& event_item : events) {
            // JSON 직렬화
            json j;
            j["timestamp"] = std::chrono::duration_cast<std::chrono::microseconds>(event_item.timestamp.time_since_epoch()).count();
            j["container_name"] = event_item.container_name;
            j["syscall"] = event_item.syscall;
            j["is_enter"] = event_item.is_enter;
            j["pid_namespace"] = event_item.pid_namespace;
            j["mnt_namespace"] = event_item.mnt_namespace;
            j["ppid"] = event_item.ppid;
            j["pid"] = event_item.pid;
            j["tid"] = event_item.tid;
            j["uid"] = event_item.uid;
            j["gid"] = event_item.gid;
            j["ret"] = event_item.ret;
            j["comm"] = event_item.comm;
            j["arg0"] = event_item.arg0;
            j["arg1"] = event_item.arg1;
            j["arg2"] = event_item.arg2;
            j["arg3"] = event_item.arg3;
            j["arg4"] = event_item.arg4;
            j["arg5"] = event_item.arg5;
            j["additional_info"] = event_item.additional_info;
            j["data_type"] = "db_event"; // DB 소비자를 위한 데이터 타입 명시

            std::string message = j.dump();
            batch.emplace_back(std::move(message));
            current_batch_size += batch.back().size();

            // 배치 크기 초과 시 전송
            if (current_batch_size >= max_batch_size) {
                sendBatchToKafka(batch);
                messageCount += batch.size();
                batch.clear();
                current_batch_size = 0;
            }
        }

        // 남은 메시지 전송
        if (!batch.empty()) {
            sendBatchToKafka(batch);
            messageCount += batch.size();
        }

        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        // std::cout << "Sent " << messageCount << " messages to Kafka in " << duration << " ms." << std::endl;
        std::cout << "Events per second: " << (double)messageCount / duration << std::endl;
    });
}


// Kafka에 배치 전송
void EventLogger::sendBatchToKafka(const std::vector<std::string>& batch) {
    for (const auto& msg : batch) {
        RdKafka::ErrorCode resp = producer_->produce(
            topic_, 
            RdKafka::Topic::PARTITION_UA, 
            RdKafka::Producer::RK_MSG_COPY, 
            const_cast<char*>(msg.data()), 
            msg.size(),
            nullptr, // 키 없음
            nullptr  // 사용자 데이터 없음
        );

        if (resp != RdKafka::ERR_NO_ERROR) {
            std::cerr << "Failed to produce to Kafka: " << RdKafka::err2str(resp) << std::endl;
        }
    }

    // 배치 전송 후 한 번만 호출하여 이벤트 처리
    producer_->poll(0);
}
