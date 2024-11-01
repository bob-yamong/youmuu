// EventLogger.cpp
#include "EventLogger.h"
#include <iostream>
#include <iomanip>
#include <exception>
#include <cstring>

// 정적 assert로 구조체 크기 검증 (eBPF와 C++ 간 일치 확인)
static_assert(sizeof(event) == 8 + 8 + 4 + 4 + 4 + 4 + 4 + 8 + TASK_COMM_LEN + 16 + 48 + MAX_FILENAME_LEN + (MAX_ARGS * MAX_ARG_LEN) + MAX_CGROUP_NAME_LEN,
              "Size of event struct does not match expected size");

EventLogger::EventLogger(size_t bufferSize, const std::string& logFilePath)
    : bufferSize_(bufferSize),
      logFilePath_(logFilePath),
      buffer1_(),
      buffer2_(),
      currentBuffer_(&buffer1_),
      flushBuffer_(&buffer2_),
      isFlushing_(false),
      shutdown_(false)
{
    buffer1_.reserve(bufferSize_);
    buffer2_.reserve(bufferSize_);
    
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
    
    // 마지막 버퍼 플러시
    std::lock_guard<std::mutex> lock(mtx_);
    if (!currentBuffer_->empty()) {
        flushToFile(*currentBuffer_);
        currentBuffer_->clear();
    }
}

void EventLogger::addEvent(const event& e)
{
    std::unique_lock<std::mutex> lock(mtx_);
    currentBuffer_->push_back(e);
    
    if (currentBuffer_->size() >= bufferSize_ && !isFlushing_.load()) {
        isFlushing_.store(true);
        // 현재 버퍼를 플러시 버퍼로 교체
        std::swap(currentBuffer_, flushBuffer_);
        // 플러시 쓰레드에게 알림
        cv_.notify_one();
    }
}

void EventLogger::flushThreadFunc()
{
    try {
        while (!shutdown_.load()) {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]() { return isFlushing_.load() || shutdown_.load(); });
            
            if (shutdown_.load() && flushBuffer_->empty()) {
                break;
            }
            
            if (isFlushing_.load() && !flushBuffer_->empty()) {
                // 플러시 플래그 해제
                isFlushing_.store(false);
                
                // 플러시 버퍼 복사
                std::vector<event> bufferToFlush;
                bufferToFlush.swap(*flushBuffer_);
                
                lock.unlock();
                
                // 파일에 기록
                flushToFile(bufferToFlush);
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
        std::ofstream ofs(logFilePath_, std::ios::app);
        if (!ofs.is_open()) {
            std::cerr << "Failed to open log file: " << logFilePath_ << std::endl;
            return;
        }
        
        for (const auto& e : buffer) {
            ofs << "[" << std::setw(13) << std::setfill('0') << e.cnt << "] "
                << "Process syscall: " << e.syscall
                << " (nr=" << e.syscall_nr
                << ", pid=" << e.pid
                << ", tid=" << e.tid
                << ", ppid=" << e.ppid
                << ", uid=" << e.uid
                << ", comm=" << e.comm
                << ", cgroup_id=" << e.cgroup_id
                << ", cgroup_name=" << e.cgroup_name << ")\n";
            
            // 시스템 콜 별 처리
            switch (e.syscall_nr)
            {
                // 프로세스 관련
                case __NR_fork:
                case __NR_vfork:
                case __NR_clone:
                    ofs << "New process creation\n";
                    break;
                case __NR_execve:
                    ofs << "Executing new program: " << e.filename << "\n";
                    for (int i = 0; i < MAX_ARGS && e.argv[i][0] != '\0'; i++) {
                        ofs << "Arg " << i << ": " << e.argv[i] << "\n";
                    }
                    break;
                case __NR_exit:
                case __NR_exit_group:
                    ofs << "Process exit\n";
                    break;
                case __NR_wait4:
                case __NR_waitid:
                    ofs << "Waiting for child process\n";
                    break;
                case __NR_kill:
                case __NR_tkill:
                case __NR_tgkill:
                    ofs << "Sending signal " << e.args[1] << " to process/thread\n";
                    break;
                case __NR_ptrace:
                    ofs << "Ptrace call with request " << e.args[0] << "\n";
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
                        ofs << "File operation: " << e.syscall << " on file: " << e.filename << "\n";
                    }
                    break;
                case __NR_close:
                    ofs << "Closing file descriptor: " << e.args[0] << "\n";
                    break;
                case __NR_read:
                case __NR_write:
                    ofs << ((e.syscall_nr == __NR_read) ? "Read" : "Write")
                        << " operation on fd " << e.args[0]
                        << ", " << e.args[2] << " bytes\n";
                    break;
                case __NR_mount:
                    ofs << "Mounting filesystem\n";
                    break;
                case __NR_umount2:
                    ofs << "Unmounting filesystem\n";
                    break;
        
                // 네트워크 관련
                case __NR_socket:
                    ofs << "Creating socket: domain " << e.args[0]
                        << ", type " << e.args[1]
                        << ", protocol " << e.args[2] << "\n";
                    break;
                case __NR_connect:
                    ofs << "Connecting to socket\n";
                    break;
                case __NR_accept:
                    ofs << "Accepting connection on socket\n";
                    break;
                case __NR_bind:
                    ofs << "Binding socket\n";
                    break;
                case __NR_listen:
                    ofs << "Listening on socket\n";
                    break;
                case __NR_sendto:
                case __NR_recvfrom:
                    ofs << ((e.syscall_nr == __NR_sendto) ? "Sending" : "Receiving")
                        << " on socket " << e.args[0]
                        << ", " << e.args[2] << " bytes\n";
                    break;
                case __NR_setsockopt:
                case __NR_getsockopt:
                    ofs << ((e.syscall_nr == __NR_setsockopt) ? "Setting" : "Getting")
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
                    ofs << "Changing process attributes: " << e.syscall << "\n";
                    break;
                case __NR_prctl:
                    ofs << "Process control operation: " << e.args[0] << "\n";
                    break;
                case __NR_setpriority:
                case __NR_sched_setscheduler:
                case __NR_sched_setparam:
                case __NR_sched_setaffinity:
                    ofs << "Changing process scheduling: " << e.syscall << "\n";
                    break;
                case __NR_sched_yield:
                    ofs << "Yielding processor\n";
                    break;
                case __NR_mprotect:
                    ofs << "mprotect called with addr=" << e.args[0]
                        << ", len=" << e.args[1]
                        << ", prot=" << e.args[2] << "\n";
                    break;
                case __NR_mmap:
                    ofs << "mmap called with addr=" << e.args[0]
                        << ", len=" << e.args[1]
                        << ", prot=" << e.args[2]
                        << ", flags=" << e.args[3]
                        << ", fd=" << e.args[4]
                        << ", offset=" << e.args[5] << "\n";
                    break;
                case __NR_munmap:
                    ofs << "munmap called with addr=" << e.args[0]
                        << ", len=" << e.args[1] << "\n";
                    break;
                default:
                    ofs << "Other system call: " << e.syscall << "\n";
                    break;
            }
        }
        
        ofs.close();
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in flushToFile: " << ex.what() << "\n";
    }
    catch (...) {
        std::cerr << "Unknown exception in flushToFile\n";
    }
}
