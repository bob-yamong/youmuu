#ifndef EVENTLOGGER_H
#define EVENTLOGGER_H

#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <condition_variable>
#include <deque>
#include <zlib.h>
#include <sys/sysinfo.h>
#include <ctime>
#include <pqxx/pqxx>
#include <syscall.h>
#include "event.h"
#include "container_info.h"

class EventLogger {
public:
    // 생성자: 버퍼 크기 설정 및 로그 파일 경로 설정
    EventLogger(size_t bufferSize, const std::string& logFilePath, const std::string& dbConnStr);
    
    // 소멸자: 모든 쓰레드 종료 및 리소스 정리
    ~EventLogger();
    
    // 로그 이벤트 추가
    void addEvent(const event& e);
    
private:
    // 로그를 파일에 기록하는 함수
    void flushThreadFunc();
    void flushToFile(const std::vector<event>& buffer);
    
    // 데이터베이스에 이벤트 삽입
    void insertEventsToDB(const std::vector<event>& buffer);

    static time_t get_boot_time();
    std::string format_timestamp(uint64_t timestamp_ns) const;

    size_t bufferSize_;
    std::string logFilePath_;
    
    // 4개의 버퍼
    std::vector<event> buffer1_;
    std::vector<event> buffer2_;
    std::vector<event> buffer3_;
    std::vector<event> buffer4_;
    
    // 현재 버퍼와 플러시 버퍼 대기열
    std::vector<event>* currentBuffer_;
    std::deque<std::vector<event>*> flushBuffers_;
    
    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> isFlushing_;
    
    // 플러시 쓰레드 관리
    std::thread flushThread_;
    
    // 쓰레드 종료를 위한 플래그
    std::atomic<bool> shutdown_;
    
    // zlib 압축 스트림
    gzFile gzFile_; // 압축된 파일 스트림 추가

    // 데이터베이스 연결 객체
    pqxx::connection dbConnection_;
    
    time_t boot_time_;
};

#endif // EVENTLOGGER_H
