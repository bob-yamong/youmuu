#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std;

struct SystemCall {
    string id;
    string syscall_num;
    string enter_exit;
    string container_id;
    string pid;
    string ppid;
    string tid;
    string uid;
    string gid;
    string command;
    string atr[6];
    string return_value;
    string additional_info;
    string called_at;
    string created_at;
    string mnt_namespace;
    string pid_namespace;
};

class CSVParser {
public:
    // 파일을 열기위해 filename을 받아옴
    CSVParser(const string& filename);
    // 파일에서 getline함수로 한줄을 읽어서 parse_line systemcall 구조체로 변환 후 return 
    SystemCall get_next_log();
    // 파일이 끝났는지 확인, 없으면 false
    bool has_next();
private:
    ifstream file;
    string current_line;
    // 실제 로그를 파싱하는 함수
    SystemCall parse_line(const string& line);
};

class MiningDetector {
public:
    // 프로세스 별 시스템콜을 분석하여 이상행위를 탐지하는 함수
    void analyze_syscall(const SystemCall& syscall);
    // 탐지 결과를 pid, time으로 반환
    vector<pair<string, string>> get_detections() const;

private:
    struct ProcessMetrics {
        int cpu_access_count = 0;
        int large_mmap_count = 0;
        int expand_heap_count = 0;
        int scheduler_count = 0;
        int connect_known_network_count = 0;
        time_t window_start = 0;
    };
    
    map<string, ProcessMetrics> process_windows;
    vector<pair<string, string>> detections;
    const int WINDOW_SIZE = 5;
};