#include "EventLogger.h"
#include <nlohmann/json.hpp>

// 편의상 네임스페이스 사용
using json = nlohmann::json;

// 생성자
EventLogger::EventLogger(size_t bufferSize, const std::string& brokers, const std::string& topic)
    : bufferSize_(bufferSize),
      buffer1_(),
      buffer2_(),
      buffer3_(),
      buffer4_(),
      currentBuffer_(&buffer1_),
      flushBuffers_(),
      isFlushing_(false),
      shutdown_(false),
      producer_(nullptr),
      topic_str_(topic),
      topic_(nullptr),
      conf_(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL)),
      tconf_(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC)),
      stop_(false)
{
    // 버퍼 예약
    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    buffer3_.reserve(bufferSize_);
    buffer4_.reserve(bufferSize_);

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
    std::lock_guard<std::mutex> lock(mtx_);
    if (!currentBuffer_->empty()) {
        flushBuffers_.push_back(currentBuffer_);
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
        flushBuffers_.push_back(currentBuffer_);

        // 다음 사용 가능한 버퍼 선택
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
    }
}

// 플러시 쓰레드 함수
void EventLogger::flushThreadFunc() {
    while (!shutdown_.load()) {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait_for(lock, this->FLUSH_TIMEOUT, [this]() { return isFlushing_.load() || shutdown_.load(); });

        if (isFlushing_.load() && !flushBuffers_.empty()) {
            std::vector<db_event_t>* bufferToFlush = flushBuffers_.front();
            flushBuffers_.pop_front();
            isFlushing_.store(false);
            lock.unlock();

            // Kafka 전송
            sendEventsToKafka(*bufferToFlush);

            // 버퍼 초기화
            bufferToFlush->clear();

            // 조건 변수 알림
            cv_.notify_all();
        }
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

    enqueueTask([this, events]() {
        auto start = std::chrono::steady_clock::now();
        size_t messageCount = 0;

        // 배치 설정
        const size_t max_batch_size = 20 * 1024 * 1024; // 20MB
        std::vector<std::string> batch;
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
    for (const auto& msg : batch) {
        RdKafka::ErrorCode resp = producer_->produce(
            topic_, 
            RdKafka::Topic::PARTITION_UA, 
            RdKafka::Producer::RK_MSG_COPY, 
            const_cast<char*>(msg.c_str()), 
            msg.size(),
            nullptr, // 키 없음
            nullptr  // 사용자 데이터 없음
        );

        if (resp != RdKafka::ERR_NO_ERROR) {
            std::cerr << "Failed to produce to Kafka: " << RdKafka::err2str(resp) << std::endl;
        }

        // 비동기 처리를 위해 poll을 주기적으로 호출
        producer_->poll(0);
    }

    // 모든 메시지가 전송되었는지 확인
    producer_->flush(10000); // 최대 10초 동안 대기
}
