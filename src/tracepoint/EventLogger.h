#ifndef EVENTLOGGER_H
#define EVENTLOGGER_H

#pragma once

#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <condition_variable>
#include <deque>
#include <queue>
#include <functional>
#include <future>
#include <iostream>
#include <ctime>
#include <chrono>
#include <nlohmann/json.hpp>
#include <exception>
#include <librdkafka/rdkafkacpp.h>
#include "user_struct.h"

class EventLogger {
public:
    EventLogger(size_t bufferCount, const std::string& brokers, const std::string& topic);
    ~EventLogger();

    void addEvent(const db_event_t& e);
    void shutdown();

private:
    // 버버 변수들을 생성자 초기화 순서와 동일하게 정렬
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> stop_{false};
    std::atomic<bool> isFlushing_{false};
    
    // 버퍼 관리
    std::vector<std::vector<db_event_t>> buffers_;
    std::deque<std::vector<db_event_t>*> availableBuffers_;
    std::deque<std::vector<db_event_t>*> flushBuffers_;
    std::vector<db_event_t>* currentBuffer_;
    std::chrono::steady_clock::time_point current_buffer_time_;
    
    // 쓰레드 관련
    std::vector<std::thread> threadPool_;
    std::thread flushThread_;

    // 동기화
    std::mutex mtx_;
    std::mutex availableBuffersMutex_;
    std::mutex flushBuffersMutex_;
    std::mutex threadPoolMutex_;
    std::condition_variable cv_;
    std::condition_variable threadPoolCV_;

    // Kafka
    std::unique_ptr<RdKafka::Producer> producer_;
    std::unique_ptr<RdKafka::Topic> topic_;
    std::string topic_str_;
    std::unique_ptr<RdKafka::Conf> conf_;
    std::unique_ptr<RdKafka::Conf> tconf_;

    // 쓰레드풀 관련
    struct ThreadPoolQueue {
        std::queue<std::function<void()>> tasks;
        std::mutex mutex;
        std::condition_variable cv;
    };
    std::vector<std::unique_ptr<ThreadPoolQueue>> threadQueues_;
    std::atomic<size_t> nextQueueIndex_{0};

    // 내부 함수
    void initThreadPool();
    void flushThreadFunc();
    void threadPoolWorker(size_t queueIndex);
    void enqueueTask(std::function<void()> task);
    void sendEventsToKafka(std::vector<db_event_t>&& events);
    void sendBatchToKafka(const std::vector<std::string>& batch);

    // 상수
    static constexpr size_t bufferSize_ = 1000;
    static constexpr std::chrono::seconds FLUSH_TIMEOUT = std::chrono::seconds(5);
};
extern EventLogger* eventLogger;

#endif // EVENTLOGGER_H