// EventLogger.cpp
#include "EventLogger.h"
#include <iostream>
#include <iomanip>
#include <exception>
#include <cstring>
#include <sstream>
#include <string_view> 

EventLogger::EventLogger(size_t bufferSize, const std::string& dbConnectionStr)
    : bufferSize_(bufferSize),
      buffer1_(),
      buffer2_(),
      buffer3_(),
      buffer4_(),
      currentBuffer_(&buffer1_),
      flushBuffers_(),
      isFlushing_(false),
      shutdown_(false),
      dbConnection_(dbConnectionStr)
{
    if (!dbConnection_.is_open()) {
        throw std::runtime_error(std::string("Failed to open database connection: ") + dbConnection_.dbname());
    }

    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    buffer3_.reserve(bufferSize_);
    buffer4_.reserve(bufferSize_);


    // 초기 버퍼 활성화 시간 설정
    current_buffer_time_ = std::chrono::steady_clock::now();

    // 플러시 쓰레드 시작
    flushThread_ = std::thread(&EventLogger::flushThreadFunc, this);
}

EventLogger::~EventLogger()
{
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
        insertEventsToDB(*bufferToFlush);
        bufferToFlush->clear();
    }

}

void EventLogger::addEvent(const db_event_t& e)
{
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

                    // DB 전송 
                    insertEventsToDB(*bufferToFlush);

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

using namespace std::string_view_literals;

void EventLogger::insertEventsToDB(const std::vector<db_event_t>& events) {
    if (events.empty()) return;

    try {
        pqxx::work txn(dbConnection_);
        auto stream = pqxx::stream_to::table(txn, {"ContainerLog"sv}, {
            "systemcall"sv,
            "enter_or_exit"sv,
            "container_name"sv,
            "pid"sv,
            "ppid"sv,
            "tid"sv,
            "uid"sv,
            "gid"sv,
            "command"sv,
            "atr_0"sv,
            "atr_1"sv,
            "atr_2"sv,
            "atr_3"sv,
            "atr_4"sv,
            "atr_5"sv,
            "return_value"sv,
            "additional_info"sv,
            "called_at"sv,
            "mnt_namespace"sv,
            "pid_namespace"sv,
        });

        for (const auto& event : events) {
            auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                event.timestamp.time_since_epoch()
            ).count();
            
            auto seconds = microseconds / 1000000;
            auto remainingMicros = microseconds % 1000000;
            
            // PostgreSQL timestamp 문자열 생성
            std::time_t time = seconds;
            std::tm* tm = std::gmtime(&time);
            char date_str[32];
            std::strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm);
            
            std::stringstream timestamp_str;
            timestamp_str << date_str << "." << std::setfill('0') << std::setw(6) << remainingMicros;

            stream.write_values(
                event.syscall,
                event.is_enter,
                event.container_name,
                event.pid,
                event.ppid,
                event.tid,
                event.uid,
                event.gid,
                event.comm,
                event.arg0,
                event.arg1,
                event.arg2,
                event.arg3,
                event.arg4,
                event.arg5,
                event.ret,
                event.additional_info,
                timestamp_str.str(),
                event.mnt_namespace,
                event.pid_namespace 
            );
        }

        stream.complete();
        txn.commit();
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to insert events: " + std::string(e.what()));
    }
}