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
#include <nlohmann/json.hpp>
#include <librdkafka/rdkafkacpp.h>
#include "user_struct.h"

class EventLogger {
public:
    EventLogger(size_t bufferSize, const std::string& brokers, const std::string& topic);
    ~EventLogger();
    void addEvent(const db_event_t& e);

private:
    void flushThreadFunc();
    void sendEventsToKafka(const std::vector<db_event_t>& buffer);
    void sendBatchToKafka(const std::vector<std::string>& batch);
    
    // 쓰레드풀 관련
    void threadPoolWorker();
    void enqueueTask(std::function<void()> task);

    size_t bufferSize_;
    std::vector<db_event_t> buffer1_;
    std::vector<db_event_t> buffer2_;
    std::vector<db_event_t> buffer3_;
    std::vector<db_event_t> buffer4_;
    std::vector<db_event_t>* currentBuffer_;
    std::deque<std::vector<db_event_t>*> flushBuffers_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> isFlushing_;
    std::thread flushThread_;
    std::atomic<bool> shutdown_;

    // Kafka 관련
    RdKafka::Producer* producer_;
    std::string topic_str_;
    RdKafka::Topic* topic_;
    RdKafka::Conf* conf_;
    RdKafka::Conf* tconf_;

    // 쓰레드풀
    std::vector<std::thread> threadPool_;
    std::mutex threadPoolMutex_;
    std::condition_variable threadPoolCV_;
    std::queue<std::function<void()>> tasks_;
    bool stop_;

    // 플러시 타임아웃 설정 (10초)
    const std::chrono::seconds FLUSH_TIMEOUT = std::chrono::seconds(10);
};
extern EventLogger* eventLogger;

#endif // EVENTLOGGER_H