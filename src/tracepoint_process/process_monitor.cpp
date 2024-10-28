// SPDX-License-Identifier: GPL-2.0
#include <iostream>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>
#include <signal.h>
#include <unistd.h>
#include <string>
#include <iomanip>
#include <atomic>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"
#include "container_info.h"
#include "syscall_list.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/async.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include <unordered_map>
#include <functional>

// 글로벌 로거 포인터 정의
std::shared_ptr<spdlog::logger> global_logger;

// 작업 스레드 종료 플래그
std::atomic<bool> stop_workers(false);
struct process_monitor_bpf *skel;
std::atomic<bool> ringbuf_thread_running(true);
static std::atomic<bool> exiting(false);
int rb_cnt_1 = 0;
int rb_cnt_2 = 0;

// 글로벌 맵 정의: 시스템 콜 번호를 로그 처리 함수로 매핑
std::unordered_map<int, std::function<void(const struct event*)>> syscall_logger_map;

// 맵 초기화 함수
void init_syscall_logger_map()
{
    // 글로벌 로거 포인터 사용
    auto logger = global_logger;
    if (!logger)
    {
        std::cerr << "Logger not initialized!\n";
        return;
    }

    // 프로세스 관련 시스템 콜 핸들러
    syscall_logger_map[__NR_fork] = [logger](const struct event *e) {
        logger->info("New process creation");
    };
    syscall_logger_map[__NR_vfork] = [logger](const struct event *e) {
        logger->info("New process creation (vfork)");
    };
    syscall_logger_map[__NR_clone] = [logger](const struct event *e) {
        logger->info("New process creation (clone)");
    };
    syscall_logger_map[__NR_execve] = [logger](const struct event *e) {
        logger->info("Executing new program: {}", e->filename);
        for (int i = 0; i < MAX_ARGS && e->argv[i][0] != '\0'; i++)
        {
            logger->info("Arg {}: {}", i, e->argv[i]);
        }
    };
    syscall_logger_map[__NR_exit] = [logger](const struct event *e) {
        logger->info("Process exit");
    };
    syscall_logger_map[__NR_exit_group] = [logger](const struct event *e) {
        logger->info("Process exit (group)");
    };
    syscall_logger_map[__NR_wait4] = [logger](const struct event *e) {
        logger->info("Waiting for child process");
    };
    syscall_logger_map[__NR_waitid] = [logger](const struct event *e) {
        logger->info("Waiting for child process (id)");
    };
    syscall_logger_map[__NR_kill] = [logger](const struct event *e) {
        logger->info("Sending signal {} to process/thread", e->args[1]);
    };
    syscall_logger_map[__NR_tkill] = [logger](const struct event *e) {
        logger->info("Sending signal {} to process/thread (tkill)", e->args[1]);
    };
    syscall_logger_map[__NR_tgkill] = [logger](const struct event *e) {
        logger->info("Sending signal {} to process/thread (tgkill)", e->args[1]);
    };
    syscall_logger_map[__NR_ptrace] = [logger](const struct event *e) {
        logger->info("Ptrace call with request {}", e->args[0]);
    };

    // 파일 시스템 관련 시스템 콜 핸들러
    std::vector<int> fs_syscalls = {
        __NR_open, __NR_openat, __NR_unlink, __NR_unlinkat, __NR_mkdir, __NR_mkdirat,
        __NR_rmdir, __NR_renameat, __NR_renameat2, __NR_symlink, __NR_symlinkat,
        __NR_link, __NR_linkat, __NR_chmod, __NR_fchmodat, __NR_chown, __NR_lchown,
        __NR_fchownat, __NR_access, __NR_faccessat, __NR_stat, __NR_lstat,
        __NR_newfstatat, __NR_truncate, __NR_readlink, __NR_readlinkat
    };
    for(auto syscall_nr : fs_syscalls)
    {
        // syscalls with similar handling can share the same lambda
        syscall_logger_map[syscall_nr] = [logger](const struct event *e) {
            if (e->filename[0] != '\0')
            {
                logger->info("File operation: {} on file: {}", e->syscall, e->filename);
            }
        };
    }

    // 추가 파일 시스템 관련 시스템 콜 핸들러
    syscall_logger_map[__NR_close] = [logger](const struct event *e) {
        logger->info("Closing file descriptor: {}", e->args[0]);
    };
    syscall_logger_map[__NR_read] = [logger](const struct event *e) {
        logger->info("Read operation on fd {}, {} bytes", e->args[0], e->args[2]);
    };
    syscall_logger_map[__NR_write] = [logger](const struct event *e) {
        logger->info("Write operation on fd {}, {} bytes", e->args[0], e->args[2]);
    };
    syscall_logger_map[__NR_mount] = [logger](const struct event *e) {
        logger->info("Mounting filesystem");
    };
    syscall_logger_map[__NR_umount2] = [logger](const struct event *e) {
        logger->info("Unmounting filesystem");
    };

    // 네트워크 관련 시스템 콜 핸들러
    syscall_logger_map[__NR_socket] = [logger](const struct event *e) {
        logger->info("Creating socket: domain {}, type {}, protocol {}",
                    e->args[0], e->args[1], e->args[2]);
    };
    syscall_logger_map[__NR_connect] = [logger](const struct event *e) {
        logger->info("Connecting to socket");
    };
    syscall_logger_map[__NR_accept] = [logger](const struct event *e) {
        logger->info("Accepting connection on socket");
    };
    syscall_logger_map[__NR_bind] = [logger](const struct event *e) {
        logger->info("Binding socket");
    };
    syscall_logger_map[__NR_listen] = [logger](const struct event *e) {
        logger->info("Listening on socket");
    };
    syscall_logger_map[__NR_sendto] = [logger](const struct event *e) {
        logger->info("Sending on socket {}, {} bytes", e->args[0], e->args[2]);
    };
    syscall_logger_map[__NR_recvfrom] = [logger](const struct event *e) {
        logger->info("Receiving on socket {}, {} bytes", e->args[0], e->args[2]);
    };
    syscall_logger_map[__NR_setsockopt] = [logger](const struct event *e) {
        logger->info("Setting socket option");
    };
    syscall_logger_map[__NR_getsockopt] = [logger](const struct event *e) {
        logger->info("Getting socket option");
    };

    // 프로세스 제어 관련 시스템 콜 핸들러
    std::vector<int> proc_ctrl_syscalls = {
        __NR_setpgid, __NR_setsid, __NR_setuid, __NR_setgid, __NR_setreuid,
        __NR_setregid, __NR_setresuid, __NR_setresgid, __NR_setgroups,
        __NR_capset, __NR_prctl, __NR_setpriority, __NR_sched_setscheduler,
        __NR_sched_setparam, __NR_sched_setaffinity, __NR_sched_yield,
        __NR_mprotect, __NR_mmap, __NR_munmap
    };
    for(auto syscall_nr : proc_ctrl_syscalls)
    {
        // 각 syscall_nr를 값으로 캡처하여 람다에 전달
        syscall_logger_map[syscall_nr] = [logger, syscall_nr](const struct event *e) {
            switch(syscall_nr)
            {
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
                    logger->info("Changing process attributes: {}", e->syscall);
                    break;
                case __NR_prctl:
                    logger->info("Process control operation: {}", e->args[0]);
                    break;
                case __NR_setpriority:
                case __NR_sched_setscheduler:
                case __NR_sched_setparam:
                case __NR_sched_setaffinity:
                    logger->info("Changing process scheduling: {}", e->syscall);
                    break;
                case __NR_sched_yield:
                    logger->info("Yielding processor");
                    break;
                case __NR_mprotect:
                    logger->info("mprotect called with addr={}, len={}, prot={}",
                                e->args[0], e->args[1], e->args[2]);
                    break;
                case __NR_mmap:
                    logger->info("mmap called with addr={}, len={}, prot={}, flags={}, fd={}, offset={}",
                                e->args[0], e->args[1], e->args[2], e->args[3], e->args[4], e->args[5]);
                    break;
                case __NR_munmap:
                    logger->info("munmap called with addr={}, len={}", e->args[0], e->args[1]);
                    break;
                default:
                    logger->info("Other system call: {}", e->syscall);
                    break;
            }
        };
    }

    // 기본 핸들러: 맵에 없는 시스템 콜 번호에 대한 처리
    syscall_logger_map[-1] = [logger](const struct event *e) {
        logger->info("Other system call: {}", e->syscall);
    };
}

// 맵 기반 접근 방식을 사용하는 로깅 함수
void logging(const struct event *e){
    try
    {
        // 일반 이벤트 정보 로그
        global_logger->info("[{:013}] Process syscall: {} (nr={}, pid={}, tid={}, ppid={}, uid={}, comm={}, cgroup_id={}, cgroup_name={})",
                    e->cnt, e->syscall, e->syscall_nr, e->pid, e->tid, e->ppid, e->uid, e->comm, e->cgroup_id, e->cgroup_name);
        
        // 시스템 콜 번호를 기반으로 맵에서 핸들러 찾기
        auto it = syscall_logger_map.find(e->syscall_nr);
        if(it != syscall_logger_map.end())
        {
            it->second(e); // 해당 핸들러 호출
        }
        else
        {
            // 기본 핸들러 호출
            syscall_logger_map[-1](e);
        }
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cerr << "spdlog 예외 발생: " << ex.what() << "\n";
    }
}

// 링버퍼 핸들러1
static int handle_event1(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event *>(data);
    // 디버그 메시지
    rb_cnt_1++;
    if (rb_cnt_1 % 100000 == 0)
        std::cout << "handle_event1 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";

    // 로그 기록
    logging(e);

    return 0;
}

// 링버퍼 핸들러2
static int handle_event2(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event *>(data);
    // 디버그 메시지
    rb_cnt_2++;
    if (rb_cnt_2 % 100000 == 0)
        std::cout << "handle_event2 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";

    // 로그 기록
    logging(e);

    return 0;
}

// 링버퍼 소비 스레드 함수
void ringbuf_thread_func(struct ring_buffer *rb)
{
    while (ringbuf_thread_running.load(std::memory_order_relaxed))
    {
        int err = ring_buffer__poll(rb, 1); // 100ms 타임아웃
        if (err == -EINTR)
        {
            break;
        }
        if (err < 0)
        {
            std::cerr << "Error polling ring buffer: " << err << "\n";
            break;
        }
    }
}

// 시그널 핸들러
static void sig_handler(int sig)
{
    exiting.store(true, std::memory_order_relaxed);
    stop_workers.store(true, std::memory_order_relaxed);
    ringbuf_thread_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char **argv)
{
    int err;

    // 시그널 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    try
    {
        // 비동기 로깅 초기화
        try
        {
            const int num_workers = std::thread::hardware_concurrency() * 2;
            // 큐 사이즈와 스레드 수 설정 (배치 처리 용이)
            spdlog::init_thread_pool(100000, num_workers); // 큐 사이즈 100,000, 워커 스레드 수

            // 글로벌 로거 포인터 초기화
            global_logger = spdlog::basic_logger_mt<spdlog::async_factory>("logger", "./log/general.log");
            global_logger->set_pattern("%v"); // 로그 패턴 단순화

            // 배치 플러시 설정 (예: 1000ms마다 플러시)
            spdlog::flush_every(std::chrono::milliseconds(100));

            // 글로벌 로거를 기본 로거로 설정
            spdlog::set_default_logger(global_logger);
        }
        catch (const spdlog::spdlog_ex &ex)
        {
            std::cerr << "spdlog 초기화 실패: " << ex.what() << "\n";
            return 1;
        }

        // BPF 애플리케이션 로드 및 검증
        skel = process_monitor_bpf__open_and_load();
        if (!skel)
        {
            std::cerr << "Failed to load BPF skeleton.\n";
            return 1;
        }

        // BPF 프로그램 연결
        err = process_monitor_bpf__attach(skel);
        if (err)
        {
            std::cerr << "Failed to attach BPF skeleton.\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }

        std::cout << "BPF 프로그램을 성공적으로 시작했습니다! 프로세스 모니터링을 시작합니다...\n";

        std::cout << "컨테이너 PID 자동 감지 중...\n";
        int detected_containers = ContainerManager::getContainerPIDs();
        if (detected_containers <= 0)
        {
            std::cerr << "실행 중인 컨테이너를 찾을 수 없습니다.\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }
        std::cout << detected_containers << "개의 컨테이너를 감지했습니다.\n";

        for (const auto &container : ContainerManager::containers)
        {
            __u32 key_pid = static_cast<__u32>(container.pid);
            __u32 value_pid = 1;
            __u64 key_inode = static_cast<__u64>(ContainerManager::getContainerInode(container.id));
            __u64 value_inode = 1;

            err = bpf_map__update_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), &value_pid, sizeof(value_pid), BPF_ANY);
            if (err)
            {
                std::cerr << "컨테이너 PID " << container.pid << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                continue;
            }

            err = bpf_map__update_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), &value_inode, sizeof(value_inode), BPF_ANY);
            if (err)
            {
                std::cerr << "컨테이너 inode " << key_inode << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                // PID 맵에서 제거
                bpf_map__delete_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), BPF_ANY);
                continue;
            }

            std::cout << "컨테이너 ID: " << container.id << ", PID: " << container.pid << ", inode: " << key_inode << "를 모니터링 중\n";
        }

        init_syscall_map(skel); // 기존 함수 호출 (필요 시 수정)

        // 시스템 콜 핸들러 맵 초기화
        init_syscall_logger_map();

        // 링버퍼 설정
        struct ring_buffer *rb1 = ring_buffer__new(bpf_map__fd(skel->maps.events_1), handle_event1, NULL, NULL);
        struct ring_buffer *rb2 = ring_buffer__new(bpf_map__fd(skel->maps.events_2), handle_event2, NULL, NULL);
        if (!rb1 || !rb2)
        {
            std::cerr << "Failed to create ring buffer\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }

        // 링버퍼 읽기 스레드 생성
        std::thread ringbuf_thread1(ringbuf_thread_func, rb1);
        std::thread ringbuf_thread2(ringbuf_thread_func, rb2);

        // 메인 루프
        while (!exiting.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // 링버퍼 읽기 스레드 종료 요청
        ringbuf_thread_running.store(false, std::memory_order_relaxed);
        ringbuf_thread1.join();
        ringbuf_thread2.join();

        // 링버퍼 정리
        ring_buffer__free(rb1);
        ring_buffer__free(rb2);

        // BPF 스켈레톤 정리
        process_monitor_bpf__destroy(skel);

        // 비동기 로깅 종료
        spdlog::shutdown();
    }
    catch (const std::bad_alloc &e)
    {
        std::cerr << "Memory allocation failed: " << e.what() << "\n";
        if (skel)
            process_monitor_bpf__destroy(skel);
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        if (skel)
            process_monitor_bpf__destroy(skel);
        return 1;
    }

    return err < 0 ? -err : 0;
}
