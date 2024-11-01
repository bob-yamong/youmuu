// EventLogger.h
#ifndef EVENTLOGGER_H
#define EVENTLOGGER_H

#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <fstream>
#include <string>
#include <condition_variable>
#include <sys/syscall.h>
#include <linux/types.h>
#include "event.h" // event 구조체가 정의된 헤더 파일

class EventLogger {
public:
    // 생성자: 버퍼 크기 설정 및 로그 파일 경로 설정
    EventLogger(size_t bufferSize, const std::string& logFilePath);
    
    // 소멸자: 모든 쓰레드 종료 및 리소스 정리
    ~EventLogger();
    
    // 로그 이벤트 추가
    void addEvent(const event& e);
    
private:
    // 로그를 파일에 기록하는 함수
    void flushThreadFunc();
    void flushToFile(const std::vector<event>& buffer);
    
    size_t bufferSize_;
    std::string logFilePath_;
    
    std::vector<event> buffer1_;
    std::vector<event> buffer2_;
    std::vector<event>* currentBuffer_;
    std::vector<event>* flushBuffer_;
    
    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> isFlushing_;
    
    // 플러시 쓰레드 관리
    std::thread flushThread_;
    
    // 쓰레드 종료를 위한 플래그
    std::atomic<bool> shutdown_;
};

#endif // EVENTLOGGER_H
