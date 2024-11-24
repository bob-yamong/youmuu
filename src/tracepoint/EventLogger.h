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
#include <sys/sysinfo.h>
#include <ctime>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <exception>
#include <cstring>
#include <sstream>
#include <string_view> 
#include <syslog.h> // syslog 헤더 추가

#include "struct.h"
#include "user_struct.h"

class EventLogger {
public:
    // 생성자: 버퍼 크기 설정
    EventLogger(size_t bufferSize);
    
    // 소멸자: 모든 쓰레드 종료 및 리소스 정리
    ~EventLogger();
    
    // 로그 이벤트 추가
    void addEvent(const db_event_t& e);
    
private:
    // 로그를 syslog에 기록하는 함수
    void flushThreadFunc();
    
    // CEF 포맷으로 변환하여 syslog에 전송
    void sendEventsAsCEF(const std::vector<db_event_t>& buffer);

    size_t bufferSize_;
    
    // 4개의 버퍼
    std::vector<db_event_t> buffer1_;
    std::vector<db_event_t> buffer2_;
    std::vector<db_event_t> buffer3_;
    std::vector<db_event_t> buffer4_;

    // 버퍼의 마지막 활성화 시간
    std::chrono::steady_clock::time_point current_buffer_time_;

    // 플러시 타임아웃 설정 (10초)
    const std::chrono::seconds FLUSH_TIMEOUT = std::chrono::seconds(10);
    
    // 현재 버퍼와 플러시 버퍼 대기열
    std::vector<db_event_t>* currentBuffer_;
    std::deque<std::vector<db_event_t>*> flushBuffers_;
    
    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> isFlushing_;
    
    // 플러시 쓰레드 관리
    std::thread flushThread_;
    
    // 쓰레드 종료를 위한 플래그
    std::atomic<bool> shutdown_;
};

extern EventLogger* eventLogger;

#endif // EVENTLOGGER_H
