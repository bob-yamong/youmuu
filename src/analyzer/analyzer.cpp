#include "analyzer.h"

#define MEMORY_SIZE 64 * 1024 * 1024    // 64MB 이상

CSVParser::CSVParser(const string& filename) {
    file.open(filename);
}

SystemCall CSVParser::get_next_log() {
    getline(file, current_line);
    return parse_line(current_line);
}

bool CSVParser::has_next() {
    return !file.eof() && file.good();
}

SystemCall CSVParser::parse_line(const string& line) {
    SystemCall log;
    stringstream ss(line);
    string field;

    auto strip_quotes = [](string& s) {
        if (s.length() >= 2 && s.front() == '"' && s.back() == '"') {
            s = s.substr(1, s.length()-2);
        }
    };
    
    // CSV 필드 파싱
    getline(ss, field, ','); strip_quotes(field); log.id = field;
    getline(ss, field, ','); strip_quotes(field); log.syscall_num = field;
    getline(ss, field, ','); strip_quotes(field); log.enter_exit = field;
    getline(ss, field, ','); strip_quotes(field); log.container_id = field;
    getline(ss, field, ','); strip_quotes(field); log.pid = field;
    getline(ss, field, ','); strip_quotes(field); log.ppid = field;
    getline(ss, field, ','); strip_quotes(field); log.tid = field;
    getline(ss, field, ','); strip_quotes(field); log.uid = field;
    getline(ss, field, ','); strip_quotes(field); log.gid = field;
    getline(ss, field, ','); strip_quotes(field); log.command = field;
    
    // atr[0] ~ atr[5] 파싱
    for(int i = 0; i < 6; i++) {
        getline(ss, field, ',');
        strip_quotes(field);
        log.atr[i] = field;
    }
    
    getline(ss, field, ','); strip_quotes(field); log.return_value = field;
    getline(ss, field, ','); strip_quotes(field); log.additional_info = field;
    getline(ss, field, ','); strip_quotes(field); log.called_at = field;
    getline(ss, field, ','); strip_quotes(field); log.created_at = field;
    getline(ss, field, ','); strip_quotes(field); log.mnt_namespace = field;
    getline(ss, field, ','); strip_quotes(field); log.pid_namespace = field;
    
    return log;
}

time_t parse_datetime(const string& datetime) {
    tm tm = {};
    istringstream ss(datetime);
    ss >> get_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    auto tp = chrono::system_clock::from_time_t(mktime(&tm));
    return chrono::system_clock::to_time_t(tp);
}

void MiningDetector::analyze_syscall(const SystemCall& syscall) {
    int suspicious_count = 0;
    auto& metrics = process_windows[syscall.pid];

    // cout << "\n=== System Call Log ===\n";
    // cout << "syscall_num: " << syscall.syscall_num << "\n";
    // cout << "enter_exit: " << syscall.enter_exit << "\n";
    // cout << "command: " << syscall.command << "\n";
    // cout << "attributes: \n";
    // for(int i = 0; i < 6; i++) {
    //     cout << "  atr[" << i << "]: '" << syscall.atr[i] << "'\n";
    // }
    // cout << "return_value: " << syscall.return_value << "\n";
    // cout << "additional_info: " << syscall.additional_info << "\n";
    // cout << "=====================\n";
    
    // 시간 윈도우 체크
    time_t current_time = parse_datetime(syscall.called_at.substr(0, 19));
    time_t window_start = metrics.window_start;
    
    if (current_time - window_start >= WINDOW_SIZE || metrics.window_start == 0) {
        metrics = ProcessMetrics();
        metrics.window_start = parse_datetime(syscall.called_at.substr(0, 19));
    }
    
    // CPU 접근 체크 (openat -> /sys/bus/cpu/devices/)
    if (syscall.syscall_num == "257" && syscall.enter_exit == "true") {
        if (syscall.atr[1].find("/sys/bus/cpu/devices/") != string::npos) {
            cout << "PID " << syscall.pid << ": CPU access detected - " 
                 << syscall.atr[1] << endl;
            metrics.cpu_access_count++;
        }
    }
    
    // 대용량 메모리 할당 체크 (mmap)
    if (syscall.syscall_num == "9" && syscall.enter_exit == "true") {
        if (!syscall.atr[0].empty()) {
            size_t size = stoull(syscall.atr[1]);
            if (size >= MEMORY_SIZE) {
                cout << "PID " << syscall.pid << ": Large mmap detected - "
                     << size << " bytes" << endl;
                metrics.large_mmap_count++;
            }
        }
    }
    
    // 힙 확장 체크 (brk)
    if (syscall.syscall_num == "12" && syscall.enter_exit == "true") {
        cout << "PID " << syscall.pid << ": Heap expansion detected" << endl;
        metrics.expand_heap_count++;
    }
    
    // CPU 스케줄링 체크
    if ((syscall.syscall_num == "203" ||     // sched_setaffinity
         syscall.syscall_num == "144" ||     // sched_setscheduler
         syscall.syscall_num == "141") &&    // setpriority
         syscall.enter_exit == "true") {
        cout << "PID " << syscall.pid << ": Scheduler operation detected - "
             << "syscall " << syscall.syscall_num << endl;
        metrics.scheduler_count++;
    }

    // // 알려진 마이닝 풀 연결 체크
    // if (syscall.syscall_num == "42" && syscall.enter_exit == "true") {
    //     // 여기에 알려진 마이닝 풀 IP/도메인 체크 로직 추가 or 네트워크 관련으로 탐지할 만한 것 추가 현재 미구현
    //     cout << "PID " << syscall.pid << ": Network connect detected" << endl;
    //     metrics.connect_known_network_count++;
    // }
    
    // 탐지 조건 체크
    if (metrics.cpu_access_count >= 10) suspicious_count++;
    if (metrics.large_mmap_count >= 3) suspicious_count++;
    if (metrics.expand_heap_count >= 3) suspicious_count++;
    if (metrics.scheduler_count >= 10) suspicious_count++;
    
    if (suspicious_count >= 3) {
        // 아직 탐지되지 않은 경우에만 추가
        bool already_detected = false;
        for (const auto& detection : detections) {
            if (detection.first == syscall.pid) {
                already_detected = true;
                break;
            }
        }
        
        if (!already_detected) {
            detections.push_back({syscall.pid, syscall.called_at});
        }
    }
}

vector<pair<string, string>> MiningDetector::get_detections() const {
    return detections;
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            cerr << "Usage: " << argv[0] << " <path-to-csv-file>" << endl;
            return 1;
        }
        // CSVParser parser("/home/ubuntu/Desktop/youmuu/src/analyzer/btc_syscalls_1.csv");  // CSV 파일명
        // CSVParser parser("/home/ubuntu/Desktop/youmuu/src/analyzer/doge-minerd_syscalls.csv");  // CSV 파일명
        CSVParser parser(argv[1]);
        MiningDetector detector;
        int log_count = 0;
        
        cout << "Starting analysis..." << endl;
        
        while (parser.has_next()) {
            try {
                auto syscall = parser.get_next_log();
                detector.analyze_syscall(syscall);
                log_count++;
                
                if (log_count % 1000 == 0) {
                    cout << "Processed " << log_count << " logs..." << endl;
                }
            }
            catch (const exception& e) {
                cerr << "Error processing log: " << e.what() << endl;
                continue;
            }
        }
        
        cout << "\nAnalysis completed. Total logs processed: " << log_count << endl;
        
        auto detections = detector.get_detections();
        if (detections.empty()) {
            cout << "No suspicious mining activity detected." << endl;
        } else {
            cout << "\nDetected suspicious mining activity:" << endl;
            for (const auto& detection : detections) {
                cout << "PID: " << detection.first 
                     << " at time: " << detection.second << endl;
            }
        }
    }
    catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}