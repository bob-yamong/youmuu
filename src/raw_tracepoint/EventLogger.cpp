#include "EventLogger.h"

// JSON 직렬화를 위해 nlohmann/json 라이브러리 사용 (필요 시 설치)
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
      tconf_(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC))
{
    // 버퍼 예약
    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    buffer3_.reserve(bufferSize_);
    buffer4_.reserve(bufferSize_);

    // 초기 버퍼 활성화 시간 설정
    current_buffer_time_ = std::chrono::steady_clock::now();

    // Kafka 브로커 설정
    std::string errstr;
    if (conf_->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << "Kafka 설정 오류: " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    // 배치 및 압축 처리 설정
    if (conf_->set("queue.buffering.max.messages", "500000", errstr) != RdKafka::Conf::CONF_OK) { // 500,000개
        std::cerr << "Kafka 설정 오류 (queue.buffering.max.messages): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("queue.buffering.max.kbytes", "1048576", errstr) != RdKafka::Conf::CONF_OK) { // 1GB
        std::cerr << "Kafka 설정 오류 (queue.buffering.max.kbytes): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("compression.type", "gzip", errstr) != RdKafka::Conf::CONF_OK) { // gzip 압축 사용
        std::cerr << "Kafka 설정 오류 (compression.type): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("batch.size", "163840", errstr) != RdKafka::Conf::CONF_OK) { // 160KB
        std::cerr << "Kafka 설정 오류 (batch.size): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    if (conf_->set("linger.ms", "1000", errstr) != RdKafka::Conf::CONF_OK) { // 3초
        std::cerr << "Kafka 설정 오류 (linger.ms): " << errstr << std::endl;
        throw std::runtime_error("Kafka 설정 실패");
    }

    // if (conf_->set("enable.idempotence", "true", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << "Kafka 설정 오류: " << errstr << std::endl;
    //     throw std::runtime_error("Kafka 설정 실패");
    // }

    // 프로듀서 객체 생성
    producer_ = RdKafka::Producer::create(conf_, errstr);
    if (!producer_) {
        std::cerr << "Kafka 프로듀서 생성 실패: " << errstr << std::endl;
        throw std::runtime_error("Kafka 프로듀서 생성 실패");
    }

    // 토픽 객체 생성
    topic_ = RdKafka::Topic::create(producer_, topic_str_, tconf_, errstr);
    if (!topic_) {
        std::cerr << "Kafka 토픽 생성 실패: " << errstr << std::endl;
        throw std::runtime_error("Kafka 토픽 생성 실패");
    }

    delete conf_;
    delete tconf_;

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

    // 모든 버퍼 플러시
    std::lock_guard<std::mutex> lock(mtx_);

    // 현재 버퍼가 비어있지 않다면 플러시 버퍼 대기열에 추가
    if (!currentBuffer_->empty()) {
        flushBuffers_.push_back(currentBuffer_);
    }

    // 모든 플러시 버퍼 플러시
    while(!flushBuffers_.empty()) {
        std::vector<event>* bufferToFlush = flushBuffers_.front();
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
void EventLogger::addEvent(const event& e) {
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

// Kafka에 이벤트 비동기 전송 (배치 처리)
void EventLogger::sendEventsToKafka(const std::vector<event>& events) {
    if (events.empty()) return;

    // 비동기 작업 시작
    std::async(std::launch::async, [this, events]() {
        auto start = std::chrono::steady_clock::now();
        size_t messageCount = 0;

        // 비동기 전송을 위한 배치 설정
        const size_t max_batch_size = 20 * 1024 * 1024; // 20MB
        std::vector<std::string> batch;
        size_t current_batch_size = 0;

        for (const auto& event : events) {
            // event를 JSON으로 직렬화
            json j;
            j["syscall"] = event.syscall;
            j["ppid"] = event.ppid;
            j["pid"] = event.pid;
            j["tid"] = event.tid;
            j["uid"] = event.uid;
            j["gid"] = event.gid;
            j["comm"] = event.comm;
            j["arg0"] = event.args[0];
            j["arg1"] = event.args[1];
            j["arg2"] = event.args[2];
            j["arg3"] = event.args[3];
            j["arg4"] = event.args[4];
            j["arg5"] = event.args[5];
            j["cgroup_id"] = event.cgroup_id;
            j["data_type"] = "db_event"; // DB 소비자를 위한 데이터 타입 명시

            std::string message = j.dump();
            batch.push_back(message);
            current_batch_size += message.size();

            // 배치 크기 초과 시 전송
            if (current_batch_size >= max_batch_size) {
                // 배치를 비동기로 전송
                std::vector<std::string> sending_batch = std::move(batch);
                std::async(std::launch::async, [this, sending_batch]() {
                    for (const auto& msg : sending_batch) {
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
                        } else {
                            // 성공적으로 전송된 메시지 수 증가
                        }

                        // 프로듀서의 큐를 처리
                        producer_->poll(0);
                    }

                    // 모든 메시지가 전송되었는지 확인
                    producer_->flush(10000); // 최대 10초 동안 대기
                });

                // 새로운 배치 시작
                batch.clear();
                current_batch_size = 0;
                messageCount += sending_batch.size();
            }
        }

        // 남은 메시지 전송
        if (!batch.empty()) {
            std::vector<std::string> sending_batch = std::move(batch);
            std::async(std::launch::async, [this, sending_batch]() {
                for (const auto& msg : sending_batch) {
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
                    } else {
                        // 성공적으로 전송된 메시지 수 증가
                    }

                    // 프로듀서의 큐를 처리
                    producer_->poll(0);
                }

                // 모든 메시지가 전송되었는지 확인
                producer_->flush(10000); // 최대 10초 동안 대기
            });

            messageCount += sending_batch.size();
        }

        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "Sent " << messageCount << " messages to Kafka in " << duration << " ms." << std::endl;
    });
}

// 플러시 쓰레드 함수
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
                    std::vector<event>* bufferToFlush = flushBuffers_.front();
                    flushBuffers_.pop_front();

                    // 비동기 전송
                    sendEventsToKafka(*bufferToFlush);

                    // 버퍼 클리어
                    bufferToFlush->clear();
                }
            }

            // 타임아웃 체크: 10초 이상 지난 currentBuffer_이 있는지 확인
            auto now = std::chrono::steady_clock::now();

            if (std::chrono::duration_cast<std::chrono::seconds>(now - current_buffer_time_) >= FLUSH_TIMEOUT && !currentBuffer_->empty()) {
                // currentBuffer_를 플러시 버퍼 대기열에 추가
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
