// process_monitor.cpp
// SPDX-License-Identifier: GPL-2.0
#include <iostream>
#include <fstream> // 파일 스트림 포함
#include <mutex>
#include <thread>
#include <vector>
#include <signal.h>
#include <unistd.h>
#include <string>
#include <iomanip>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"
#include "container_info.h"

// concurrentqueue 헤더 포함
#include "../../concurrentqueue/concurrentqueue.h"

// concurrentqueue 정의 (Lock-Free Queue)
moodycamel::ConcurrentQueue<event> event_queue;

// 작업 스레드 종료 플래그
bool stop_workers = false;
struct process_monitor_bpf *skel;
static bool exiting = false;

// 워커 스레드 함수 수정: 각 스레드가 자체 로그 파일을 가짐
void worker_thread_func(int worker_id) {
    // 각 스레드별 로그 파일 열기
    std::ofstream log_file;
    std::string filename = "./log/worker_" + std::to_string(worker_id) + ".log";
    log_file.open(filename, std::ios::out | std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "스레드 " << worker_id << "의 로그 파일을 열 수 없습니다: " << filename << "\n";
        return;
    } else {
        std::cout << "스레드 " << worker_id << "가 로그 파일을 성공적으로 열었습니다: " << filename << "\n";
    }

    while (true) {
        event evt;
        if (event_queue.try_dequeue(evt)) {
            // 더미 이벤트인지 확인
            if (stop_workers && evt.cgroup_id == 0 && evt.syscall_nr == 0) {
                std::cerr << "스레드 " << worker_id << " 종료 신호 수신.\n";
                break;
            }

            // 이벤트 처리
            const struct event *e = &evt;
    
            // 로그 파일에 기록
            log_file << "[" 
                        << std::setw(13) << std::setfill('0') << e->cnt 
                        << "] Process syscall: " << e->syscall 
                        << " (nr=" << e->syscall_nr 
                        << ", pid=" << e->pid
                        << ", tid=" << e->tid 
                        << ", ppid=" << e->ppid 
                        << ", uid=" << e->uid 
                        << ", comm=" << e->comm
                        << ", cgroup_id=" << e->cgroup_id 
                        << ", cgroup_name=" << e->cgroup_name 
                        << ")\n";

            // 시스템 콜 별 처리
            switch (e->syscall_nr) {
                // 프로세스 관련
            case __NR_fork:
            case __NR_vfork:
            case __NR_clone:
                log_file << "New process creation\n";
                break;
            case __NR_execve:
                log_file << "Executing new program: " << e->filename << "\n";
                for (int i = 0; i < MAX_ARGS && e->argv[i][0] != '\0'; i++) {
                    log_file << "Arg " << i << ": " << e->argv[i] << "\n";
                }
                break;
            case __NR_exit:
            case __NR_exit_group:
                log_file << "Process exit\n";
                break;
            case __NR_wait4:
            case __NR_waitid:
                log_file << "Waiting for child process\n";
                break;
            case __NR_kill:
            case __NR_tkill:
            case __NR_tgkill:
                log_file << "Sending signal " << e->args[1] << " to process/thread\n";
                break;
            case __NR_ptrace:
                log_file << "Ptrace call with request " << e->args[0] << "\n";
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
                if (e->filename[0] != '\0') {
                    log_file << "File operation: " << e->syscall << " on file: " << e->filename << "\n";
                }
                break;
            case __NR_close:
                log_file << "Closing file descriptor: " << e->args[0] << "\n";
                break;
            case __NR_read:
            case __NR_write:
                log_file << (e->syscall_nr == __NR_read ? "Read" : "Write") << " operation on fd " << e->args[0]
                            << ", " << e->args[2] << " bytes\n";
                break;
            case __NR_mount:
                log_file << "Mounting filesystem\n";
                break;
            case __NR_umount2:
                log_file << "Unmounting filesystem\n";
                break;

                // 네트워크 관련
            case __NR_socket:
                log_file << "Creating socket: domain " << e->args[0] << ", type " << e->args[1]
                            << ", protocol " << e->args[2] << "\n";
                break;
            case __NR_connect:
                log_file << "Connecting to socket\n";
                break;
            case __NR_accept:
                log_file << "Accepting connection on socket\n";
                break;
            case __NR_bind:
                log_file << "Binding socket\n";
                break;
            case __NR_listen:
                log_file << "Listening on socket\n";
                break;
            case __NR_sendto:
            case __NR_recvfrom:
                log_file << (e->syscall_nr == __NR_sendto ? "Sending" : "Receiving") << " on socket " << e->args[0]
                            << ", " << e->args[2] << " bytes\n";
                break;
            case __NR_setsockopt:
            case __NR_getsockopt:
                log_file << (e->syscall_nr == __NR_setsockopt ? "Setting" : "Getting") << " socket option\n";
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
                log_file << "Changing process attributes: " << e->syscall << "\n";
                break;
            case __NR_prctl:
                log_file << "Process control operation: " << e->args[0] << "\n";
                break;
            case __NR_setpriority:
            case __NR_sched_setscheduler:
            case __NR_sched_setparam:
            case __NR_sched_setaffinity:
                log_file << "Changing process scheduling: " << e->syscall << "\n";
                break;
            case __NR_sched_yield:
                log_file << "Yielding processor\n";
                break;
            case __NR_mprotect: 
                log_file << "mprotect called with addr=" << e->args[0] << ", len=" << e->args[1] << ", prot=" << e->args[2] << "\n";
                break;
            case __NR_mmap:
                log_file << "mmap called with addr=" << e->args[0] << ", len=" << e->args[1] << ", prot=" << e->args[2]
                            << ", flags=" << e->args[3] << ", fd=" << e->args[4] << ", offset=" << e->args[5] << "\n";
                break;
            case __NR_munmap:
                log_file << "munmap called with addr=" << e->args[0] << ", len=" << e->args[1] << "\n";
                break;
            default:
                log_file << "Other system call: " << e->syscall << "\n";
                break;
            }
        } else {
            // 큐에 이벤트가 없을 경우 잠시 대기
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // 로그 파일 닫기
    log_file.close();
    std::cerr << "스레드 " << worker_id << " 종료됨.\n";
}

// 링버퍼 핸들러 수정: 이벤트를 Lock-Free 큐에 추가
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event*>(data);

    // 디버그 메시지 추가
    std::cerr << "handle_event 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";

    // 큐에 이벤트를 푸시
    event_queue.enqueue(*e);

    return 0;
}

// 시그널 핸들러
static void sig_handler(int sig)
{
    exiting = true;
    stop_workers = true;
    // 워커 스레드를 깨우기 위해 더미 이벤트 추가는 main에서 처리
}

void init_syscall_map(struct process_monitor_bpf *skel)
{
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        // 프로세스 관련
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_kill, "kill" },
        { __NR_tkill, "tkill" },
        { __NR_tgkill, "tgkill" },
        { __NR_ptrace, "ptrace" },
        { __NR_setpgid, "setpgid" },
        { __NR_setsid, "setsid" },
        { __NR_setuid, "setuid" },
        { __NR_setgid, "setgid" },
        { __NR_setreuid, "setreuid" },
        { __NR_setregid, "setregid" },
        { __NR_setresuid, "setresuid" },
        { __NR_setresgid, "setresgid" },
        { __NR_setgroups, "setgroups" },
        { __NR_prctl, "prctl" },
        { __NR_capset, "capset" },
        { __NR_setpriority, "setpriority" },
        { __NR_sched_setscheduler, "sched_setscheduler" },
        { __NR_sched_setparam, "sched_setparam" },
        { __NR_sched_setaffinity, "sched_setaffinity" },
        { __NR_sched_yield, "sched_yield" },

        // 파일 시스템 관련
        { __NR_open, "open" },
        { __NR_openat, "openat" },
        { __NR_close, "close" },
        { __NR_read, "read" },
        { __NR_write, "write" },
        { __NR_lseek, "lseek" },
        { __NR_unlink, "unlink" },
        { __NR_rename, "rename" },
        { __NR_mkdir, "mkdir" },
        { __NR_rmdir, "rmdir" },
        { __NR_chdir, "chdir" },
        { __NR_chmod, "chmod" },
        { __NR_chown, "chown" },
        { __NR_mount, "mount" },
        { __NR_umount2, "umount2" },

        // 네트워크 관련
        { __NR_socket, "socket" },
        { __NR_connect, "connect" },
        { __NR_accept, "accept" },
        { __NR_bind, "bind" },
        { __NR_listen, "listen" },
        { __NR_sendto, "sendto" },
        { __NR_recvfrom, "recvfrom" },
        { __NR_setsockopt, "setsockopt" },
        { __NR_getsockopt, "getsockopt" },
        // 기타 시스템 콜 추가
        { __NR_brk, "brk" },
        { __NR_munmap, "munmap" },
        { __NR_mprotect, "mprotect" },
        { __NR_mmap, "mmap" },
        { __NR_mremap, "mremap" },
        { __NR_getpid, "getpid" },
        { __NR_getppid, "getppid" },
        { __NR_getuid, "getuid" },
        { __NR_geteuid, "geteuid" },
        { __NR_getgid, "getgid" },
        { __NR_getegid, "getegid" },
        { __NR_times, "times" },
        { __NR_nanosleep, "nanosleep" },
        { __NR_clock_gettime, "clock_gettime" },
        { __NR_gettimeofday, "gettimeofday" },
        { __NR_settimeofday, "settimeofday" },
        { __NR_getrlimit, "getrlimit" },
        { __NR_setrlimit, "setrlimit" },
        { __NR_sysinfo, "sysinfo" },
        { __NR_getdents, "getdents" },
        { __NR_fstat, "fstat" },
        { __NR_stat, "stat" },
        { __NR_lstat, "lstat" },
        { __NR_pipe, "pipe" },
        { __NR_pipe2, "pipe2" },
        { __NR_dup, "dup" },
        { __NR_dup2, "dup2" },
        { __NR_dup3, "dup3" },
        { __NR_ioctl, "ioctl" },
        { __NR_fcntl, "fcntl" },
        { __NR_fsync, "fsync" },
        { __NR_fdatasync, "fdatasync" },
        { __NR_sync, "sync" },
        { __NR_syncfs, "syncfs" }
    };

    for (size_t i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
        int key = syscall_list[i].nr;
        char value[16] = {0};  // 16바이트 버퍼 생성
        strncpy(value, syscall_list[i].name, sizeof(value) - 1); 
        bpf_map__update_elem(skel->maps.syscall_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    }
}

int main(int argc, char **argv)
{
    int err;

    // 시그널 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    try {
        // BPF 애플리케이션 로드 및 검증
        skel = process_monitor_bpf__open_and_load();
        if (!skel) {
            std::cerr << "Failed to load BPF skeleton.\n";
            return 1;
        }

        // BPF 프로그램 연결
        err = process_monitor_bpf__attach(skel);
        if (err) {
            std::cerr << "Failed to attach BPF skeleton.\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }

        std::cout << "BPF 프로그램을 성공적으로 시작했습니다! 프로세스 모니터링을 시작합니다...\n";

        std::cout << "컨테이너 PID 자동 감지 중...\n";
        int detected_containers = ContainerManager::getContainerPIDs();
        if (detected_containers <= 0) {
            std::cerr << "실행 중인 컨테이너를 찾을 수 없습니다.\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }
        std::cout << detected_containers << "개의 컨테이너를 감지했습니다.\n";

        for (const auto& container : ContainerManager::containers) {
            __u32 key_pid = static_cast<__u32>(container.pid);
            __u32 value_pid = 1;
            __u64 key_inode = static_cast<__u64>(ContainerManager::getContainerInode(container.id));
            __u64 value_inode = 1;

            err = bpf_map__update_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), &value_pid, sizeof(value_pid), BPF_ANY);
            if (err) {
                std::cerr << "컨테이너 PID " << container.pid << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                continue;
            }

            err = bpf_map__update_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), &value_inode, sizeof(value_inode), BPF_ANY);
            if (err) {
                std::cerr << "컨테이너 inode " << key_inode << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                // PID 맵에서 제거
                bpf_map__delete_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), BPF_ANY);
                continue;
            }

            std::cout << "컨테이너 ID: " << container.id << ", PID: " << container.pid << ", inode: " << key_inode << "를 모니터링 중\n";
        }

        init_syscall_map(skel);

        // 워커 스레드 풀 생성 (CPU 코어 수에 맞춤)
        const int num_workers = std::thread::hardware_concurrency() * 2;
        std::cout << "워커 스레드 수: " << num_workers << "\n";
        std::vector<std::thread> worker_threads;
        for (int i = 0; i < num_workers; ++i) {
            worker_threads.emplace_back(worker_thread_func, i);
        }

        // 테스트 이벤트 추가 (확인용)
        for (int i = 0; i < num_workers; ++i) {
            event test_event = {};
            test_event.cgroup_id = i + 1;
            test_event.syscall_nr = 999;
            event_queue.enqueue(test_event);
        }

        // 링버퍼 설정
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            std::cerr << "Failed to create ring buffer\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }

        // 메인 루프
        while (!exiting) {
            err = ring_buffer__poll(rb, 1); // 100ms 타임아웃
            if (err == -EINTR) {
                err = 0;
                break;
            }
            if (err < 0) {
                std::cerr << "Error polling ring buffer: " << err << "\n";
                break;
            }
        }

        // 링버퍼 정리
        ring_buffer__free(rb);

        // 워커 스레드 종료 요청 및 정리
        stop_workers = true;
        // 각 워커 스레드를 깨우기 위해 더미 이벤트 추가
        for (int i = 0; i < num_workers; ++i) {
            event dummy_event = {};
            dummy_event.cgroup_id = 0;
            dummy_event.syscall_nr = 0;
            event_queue.enqueue(dummy_event);
        }
        for (auto &t : worker_threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        // BPF 스켈레톤 정리
        process_monitor_bpf__destroy(skel);
    }
    catch (const std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << "\n";
        if (skel) process_monitor_bpf__destroy(skel);
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        if (skel) process_monitor_bpf__destroy(skel);
        return 1;
    }

    return err < 0 ? -err : 0;
}
