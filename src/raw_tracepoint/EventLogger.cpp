// EventLogger.cpp
#include "EventLogger.h"
#include <iostream>
#include <iomanip>
#include <exception>
#include <cstring>
#include <sstream>
#include <zlib.h>

// 정적 assert로 구조체 크기 검증 (eBPF와 C++ 간 일치 확인)
// static_assert(sizeof(event) == 8 + 8 + 4 + 4 + 4 + 4 + 4 + 8 + 8 + TASK_COMM_LEN + 16 + 48 + MAX_FILENAME_LEN + (MAX_ARGS * MAX_ARG_LEN) + MAX_CGROUP_NAME_LEN,
//               "Size of event struct does not match expected size");

EventLogger::EventLogger(size_t bufferSize, const std::string& logFilePath , const std::string& dbConnectionStr)
    : bufferSize_(bufferSize),
      logFilePath_(logFilePath),
      buffer1_(),
      buffer2_(),
      buffer3_(),
      buffer4_(),
      currentBuffer_(&buffer1_),
      flushBuffers_(),
      isFlushing_(false),
      shutdown_(false),
      gzFile_(nullptr), // 초기화
      dbConnection_(dbConnectionStr),
      boot_time_(get_boot_time()) // boot_time 초기화
{
    if (boot_time_ == 0) {
        throw std::runtime_error("Failed to get system boot time");
    }

    if (!dbConnection_.is_open()) {
        throw std::runtime_error(std::string("Failed to open database connection: ") + dbConnection_.dbname());
    }

    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    buffer3_.reserve(bufferSize_);
    buffer4_.reserve(bufferSize_);
    
    // 압축된 파일 열기 (쓰기 모드, 압축 레벨 6)
    gzFile_ = gzopen(logFilePath_.c_str(), "wb6");
    if (!gzFile_) {
        throw std::runtime_error("Failed to open compressed log file: " + logFilePath_);
    }
    
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
    
    // 다른 버퍼들도 비어있지 않다면 플러시 버퍼 대기열에 추가
    for(auto buffer_ptr : {&buffer1_, &buffer2_, &buffer3_, &buffer4_}) {
        if(buffer_ptr != currentBuffer_ && !buffer_ptr->empty()) {
            flushBuffers_.push_back(buffer_ptr);
        }
    }
    
    // 모든 플러시 버퍼 플러시
    while(!flushBuffers_.empty()) {
        std::vector<event>* bufferToFlush = flushBuffers_.front();
        flushBuffers_.pop_front();
        flushToFile(*bufferToFlush);
        bufferToFlush->clear();
    }

    // 압축된 파일 닫기
    if (gzFile_) {
        gzclose(gzFile_);
        gzFile_ = nullptr;
    }

    // 데이터베이스 연결 종료
    if (dbConnection_.is_open()) {
        dbConnection_.disconnect();
    }
}

void EventLogger::addEvent(const event& e)
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
    }
}

void EventLogger::flushThreadFunc()
{
    try {
        while (!shutdown_.load()) {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]() { return !flushBuffers_.empty() || shutdown_.load(); });
            
            if (shutdown_.load() && flushBuffers_.empty()) {
                break;
            }
            
            if (!flushBuffers_.empty()) {
                // 플러시할 버퍼를 가져옴
                std::vector<event>* bufferToFlush = flushBuffers_.front();
                flushBuffers_.pop_front();
                
                // 플러시 플래그 해제 (대기열이 비었을 때)
                if(flushBuffers_.empty()) {
                    isFlushing_.store(false);
                }
                
                // 잠금 해제
                lock.unlock();
                
                // 파일에 기록 (압축된 형태로)
                flushToFile(*bufferToFlush);
                
                // 버퍼 클리어
                bufferToFlush->clear();
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

void EventLogger::flushToFile(const std::vector<event>& buffer)
{
    try {
        if (!gzFile_) {
            std::cerr << "Compressed log file is not open.\n";
            return;
        }

        for (const auto& e : buffer) {
            std::ostringstream oss;
            oss << "[" << std::setw(13) << std::setfill('0') << e.cnt << "] "
                << format_timestamp(e.timestamp) << " "
                << "Process syscall: " << e.syscall
                << " (nr=" << e.syscall_nr
                << ", pid=" << e.pid
                << ", tid=" << e.tid
                << ", ppid=" << e.ppid
                << ", uid=" << e.uid
                << ", comm=" << std::string(e.comm)
                << ", cgroup_id=" << e.cgroup_id
                << ", cgroup_name=" << std::string(e.cgroup_name) << ")\n";
            
            // 시스템 콜 별 처리
            switch (e.syscall_nr)
            {
                // 프로세스 관련
                case __NR_fork:
                case __NR_vfork:
                case __NR_clone:
                    oss << "New process creation\n";
                    break;
                case __NR_execve:
                case __NR_execveat:
                    oss << "Executing new program: " << std::string(e.filename) << "\n";
                    for (int i = 0; i < MAX_ARGS && e.argv[i][0] != '\0'; i++) {
                        oss << "Arg " << i << ": " << std::string(e.argv[i]) << "\n";
                    }
                    break;
                case __NR_exit:
                case __NR_exit_group:
                    oss << "Process exit\n";
                    break;
                case __NR_wait4:
                case __NR_waitid:
                    oss << "Waiting for child process\n";
                    break;
                case __NR_kill:
                case __NR_tkill:
                case __NR_tgkill:
                    oss << "Sending signal " << e.args[1] << " to process/thread\n";
                    break;
                case __NR_ptrace:
                    oss << "Ptrace call with request " << e.args[0] << "\n";
                    break;
        
                // 파일 시스템 관련
                case __NR_open:
                case __NR_openat:
                case __NR_unlink:
                case __NR_unlinkat:
                case __NR_mkdir:
                case __NR_mkdirat:
                case __NR_rmdir:
                case __NR_renameat:
                case __NR_renameat2:
                case __NR_symlink:
                case __NR_symlinkat:
                case __NR_link:
                case __NR_linkat:
                case __NR_chmod:
                case __NR_fchmodat:
                case __NR_chown:
                case __NR_lchown:
                case __NR_fchownat:
                case __NR_access:
                case __NR_faccessat:
                case __NR_stat:
                case __NR_lstat:
                case __NR_newfstatat:
                case __NR_truncate:
                case __NR_readlink:
                case __NR_readlinkat:
                    if (e.filename[0] != '\0') {
                        oss << "File operation: " << e.syscall << " on file: " << std::string(e.filename) << "\n";
                    }
                    break;
                case __NR_close:
                    oss << "Closing file descriptor: " << e.args[0] << "\n";
                    break;
                case __NR_read:
                case __NR_write:
                    oss << ((e.syscall_nr == __NR_read) ? "Read" : "Write")
                        << " operation on fd " << e.args[0]
                        << ", " << e.args[2] << " bytes\n";
                    break;
                case __NR_mount:
                    oss << "Mounting filesystem\n";
                    break;
                case __NR_umount2:
                    oss << "Unmounting filesystem\n";
                    break;
        
                // 네트워크 관련
                case __NR_socket:
                    oss << "Creating socket: domain " << e.args[0]
                        << ", type " << e.args[1]
                        << ", protocol " << e.args[2] << "\n";
                    break;
                case __NR_connect:
                    oss << "Connecting to socket\n";
                    break;
                case __NR_accept:
                    oss << "Accepting connection on socket\n";
                    break;
                case __NR_bind:
                    oss << "Binding socket\n";
                    break;
                case __NR_listen:
                    oss << "Listening on socket\n";
                    break;
                case __NR_sendto:
                case __NR_recvfrom:
                    oss << ((e.syscall_nr == __NR_sendto) ? "Sending" : "Receiving")
                        << " on socket " << e.args[0]
                        << ", " << e.args[2] << " bytes\n";
                    break;
                case __NR_setsockopt:
                case __NR_getsockopt:
                    oss << ((e.syscall_nr == __NR_setsockopt) ? "Setting" : "Getting")
                        << " socket option\n";
                    break;
        
                // 프로세스 제어 관련
                case __NR_setpgid:
                case __NR_setsid:
                case __NR_setuid:
                case __NR_setgid:
                case __NR_setreuid:
                case __NR_setregid:
                case __NR_setresuid:
                case __NR_setresgid:
                case __NR_setgroups:
                case __NR_capset:
                    oss << "Changing process attributes: " << e.syscall << "\n";
                    break;
                case __NR_prctl:
                    oss << "Process control operation: " << e.args[0] << "\n";
                    break;
                case __NR_setpriority:
                case __NR_sched_setscheduler:
                case __NR_sched_setparam:
                case __NR_sched_setaffinity:
                    oss << "Changing process scheduling: " << e.syscall << "\n";
                    break;
                case __NR_sched_yield:
                    oss << "Yielding processor\n";
                    break;
                case __NR_mprotect:
                    oss << "mprotect called with addr=" << e.args[0]
                        << ", len=" << e.args[1]
                        << ", prot=" << e.args[2] << "\n";
                    break;
                case __NR_mmap:
                    oss << "mmap called with addr=" << e.args[0]
                        << ", len=" << e.args[1]
                        << ", prot=" << e.args[2]
                        << ", flags=" << e.args[3]
                        << ", fd=" << e.args[4]
                        << ", offset=" << e.args[5] << "\n";
                    break;
                case __NR_munmap:
                    oss << "munmap called with addr=" << e.args[0]
                        << ", len=" << e.args[1] << "\n";
                    break;
                default:
                    oss << "Other system call: " << e.syscall << "\n";
                    break;
            }

            // 압축된 파일에 쓰기
            std::string logEntry = oss.str();
            int writeResult = gzwrite(gzFile_, logEntry.c_str(), logEntry.size());
            if (writeResult == 0) {
                int err_no = 0;
                const char* error_string = gzerror(gzFile_, &err_no);
                if (err_no) {
                    std::cerr << "Error writing to compressed log file: " << error_string << "\n";
                }
            }
        }

        // 데이터 플러시
        gzflush(gzFile_, Z_SYNC_FLUSH);

        // 데이터베이스에 이벤트 삽입
        insertEventsToDB(buffer);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in flushToFile: " << ex.what() << "\n";
    }
    catch (...) {
        std::cerr << "Unknown exception in flushToFile\n";
    }
}

time_t EventLogger::get_boot_time() {
    struct sysinfo s_info;
    if (sysinfo(&s_info) != 0) {
        return 0;
    }
    return time(NULL) - s_info.uptime;
}

std::string EventLogger::format_timestamp(uint64_t timestamp_ns) const {
    time_t seconds = boot_time_ + (timestamp_ns / 1000000000);
    struct tm tm_info;
    localtime_r(&seconds, &tm_info);
    
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    
    uint64_t nanoseconds = timestamp_ns % 1000000000;
    char result[48];
    snprintf(result, sizeof(result), "%s.%09lu", buffer, nanoseconds);
    
    return std::string(result);
}

void EventLogger::insertEventsToDB(const std::vector<event>& buffer)
{
    if (buffer.empty()) {
        return;
    }

    try {
        // 트랜잭션 시작
        pqxx::work txn(dbConnection_);

        // Prepared Statement 사용 (성능 향상 및 보안)
        txn.conn().prepare("insert_syscall",
            "INSERT INTO \"ContainerLog\" (systemcall, container_name, pid, ppid, tid, uid, gid, command, atr_0, atr_1, atr_2, atr_3, atr_4, atr_5) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"
        );
     

        for (const auto& e : buffer) {
            std::string container_name;
            for (const auto& container : ContainerManager::containers) {
            if (container.cgroup_id == e.cgroup_id) {
                    container_name = container.name;
                }
            }

            txn.exec_prepared("insert_syscall",
            e.syscall,
            container_name,
            e.pid,
            e.ppid,
            e.tid,
            e.uid,
            e.gid,
            std::string(e.comm),
            std::string(e.argv[0]),
            std::string(e.argv[1]),
            std::string(e.argv[2]),
            std::string(e.argv[3]),
            std::string(e.argv[4]),
            std::string(e.argv[5]));

        }

        // 트랜잭션 커밋
        txn.commit();
    }
    catch (const pqxx::sql_error &e) {
        std::cerr << "SQL error: " << e.what() << "\n";
        std::cerr << "Query was: " << e.query() << "\n";
    }
    catch (const std::exception &e) {
        std::cerr << "Exception in insertEventsToDB: " << e.what() << "\n";
    }
}

// void EventLogger::insertEventsToDB(const std::vector<event>& buffer)
// {
//     if (buffer.empty()) {
//         return;
//     }

//     try {
//         // 트랜잭션 시작
//         pqxx::work txn(dbConnection_);

//         // stream_to 사용하여 COPY 명령어 수행
//         pqxx::stream_to stream(txn, "ContainerLog");

//         for (const auto& e : buffer) {
//             std::string container_name;
//             for (const auto& container : ContainerManager::containers) {
//                 if (container.cgroup_id == e.cgroup_id) {
//                     container_name = container.name;
//                     break;
//                 }
//             }

//             // stream_to에 데이터 삽입
//             stream << pqxx::row{
//                 e.syscall,
//                 container_name,
//                 e.pid,
//                 e.ppid,
//                 e.tid,
//                 e.uid,
//                 e.gid,
//                 std::string(e.comm),
//                 std::string(e.argv[0]),
//                 std::string(e.argv[1]),
//                 std::string(e.argv[2]),
//                 std::string(e.argv[3]),
//                 std::string(e.argv[4]),
//                 std::string(e.argv[5])
//             };
//         }

//         // stream 닫기 (자동으로 트랜잭션 커밋)
//         stream.complete();

//     }
//     catch (const pqxx::sql_error &e) {
//         std::cerr << "SQL error: " << e.what() << "\n";
//         std::cerr << "Query was: " << e.query() << "\n";
//     }
//     catch (const std::exception &e) {
//         std::cerr << "Exception in insertEventsToDB: " << e.what() << "\n";
//     }
// }