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
    // 버퍼 관리
    std::vector<std::vector<db_event_t>> buffers_;
    std::deque<std::vector<db_event_t>*> availableBuffers_;
    std::deque<std::vector<db_event_t>*> flushBuffers_;
    std::vector<std::thread> threadPool_;
    std::thread flushThread_;
    std::vector<db_event_t>* currentBuffer_;
    std::chrono::steady_clock::time_point current_buffer_time_;

    // 동기화
    std::mutex mtx_;
    std::mutex availableBuffersMutex_;
    std::mutex flushBuffersMutex_;
    std::mutex threadPoolMutex_;
    std::condition_variable cv_;
    std::condition_variable threadPoolCV_;
    std::atomic<bool> isFlushing_;
    std::atomic<bool> shutdown_;
    bool stop_;

    // Kafka
    std::unique_ptr<RdKafka::Producer> producer_;
    std::unique_ptr<RdKafka::Topic> topic_;
    std::string topic_str_;
    std::unique_ptr<RdKafka::Conf> conf_;
    std::unique_ptr<RdKafka::Conf> tconf_;

    // 쓰레드풀 작업 큐
    std::queue<std::function<void()>> tasks_;

    // 내부 함수
    void flushThreadFunc();
    void threadPoolWorker();
    void enqueueTask(std::function<void()> task);
    void sendEventsToKafka(std::vector<db_event_t>&& events);
    void sendBatchToKafka(const std::vector<std::string>& batch);

    // 상수
    static constexpr size_t bufferSize_ = 1000; // 예시 버퍼 크기
    static constexpr std::chrono::seconds FLUSH_TIMEOUT = std::chrono::seconds(5);
};
extern EventLogger* eventLogger;

#endif // EVENTLOGGER_H