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
#include <atomic>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"
#include "container_info.h"
#include "syscall_list.h"

// concurrentqueue 헤더 포함
#include "../../concurrentqueue/concurrentqueue.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/async.h"
#include "spdlog/sinks/rotating_file_sink.h"

// concurrentqueue 정의 (Lock-Free Queue)
moodycamel::ConcurrentQueue<event> event_queue;

// 작업 스레드 종료 플래그
std::atomic<bool> stop_workers(false);
struct process_monitor_bpf *skel;
std::atomic<bool> ringbuf_thread_running(true);
static std::atomic<bool> exiting(false);
int rb_cnt_1 = 0;
int rb_cnt_2 = 0;

// 링버퍼 핸들러1
static int handle_event1(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event *>(data);
    // 디버그 메시지
    std::cerr << "handle_event1 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    // 큐에 이벤트 enqueue
    rb_cnt_1++;
    if (rb_cnt_1 % 100000 == 0)
        std::cout << "handle_event1 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    event_queue.enqueue(*e);
    return 0;
}

// 링버퍼 핸들러2
static int handle_event2(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event *>(data);
    // 디버그 메시지
    std::cerr << "handle_event2 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    // 큐에 이벤트 enqueue
    rb_cnt_2++;
    if (rb_cnt_2 % 100000 == 0)
        std::cout << "handle_event2 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    event_queue.enqueue(*e);
    return 0;
}

// 링버퍼 소비 스레드 함수
void ringbuf_thread_func(struct ring_buffer *rb)
{
    while (ringbuf_thread_running)
    {
        int err = ring_buffer__poll(rb, -1); // 100ms 타임아웃
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

void worker_thread_func(int worker_id)
{
    // 각 스레드별 비동기 파일 로거 생성
    std::string filename = "./log/worker_" + std::to_string(worker_id) + ".log";
    std::shared_ptr<spdlog::logger> log_file;

    try
    {
        log_file = spdlog::basic_logger_mt<spdlog::async_factory>("worker_" + std::to_string(worker_id), filename);
        log_file->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cerr << "스레드 " << worker_id << "의 로거 생성 실패: " << ex.what() << "\n";
        return;
    }

    spdlog::set_default_logger(log_file); // 기본 로거 설정 (선택 사항)

    std::cout << "스레드 " << worker_id << "가 로그 파일을 성공적으로 열었습니다: " << filename << "\n";

    while (true)
    {
        event evt;
        if (event_queue.try_dequeue(evt))
        {
            // 더미 이벤트인지 확인
            if (stop_workers.load(std::memory_order_relaxed) && evt.cgroup_id == 0 && evt.syscall_nr == 0)
            {
                spdlog::warn("스레드 {} 종료 신호 수신.", worker_id);
                break;
            }

            // 이벤트 처리 및 로깅
            log_file->info("[{:013}] Process syscall: {} (nr={}, pid={}, tid={}, ppid={}, uid={}, comm={}, cgroup_id={}, cgroup_name={})",
                           evt.cnt, evt.syscall, evt.syscall_nr, evt.pid, evt.tid, evt.ppid, evt.uid, evt.comm, evt.cgroup_id, evt.cgroup_name);

            // 시스템 콜 별 처리
            switch (evt.syscall_nr)
            {
                // 프로세스 관련
            case __NR_fork:
            case __NR_vfork:
            case __NR_clone:
                log_file->info("New process creation");
                break;
            case __NR_execve:
                log_file->info("Executing new program: {}", evt.filename);
                for (int i = 0; i < MAX_ARGS && evt.argv[i][0] != '\0'; i++)
                {
                    log_file->info("Arg {}: {}", i, evt.argv[i]);
                }
                break;
            case __NR_exit:
            case __NR_exit_group:
                log_file->info("Process exit");
                break;
            case __NR_wait4:
            case __NR_waitid:
                log_file->info("Waiting for child process");
                break;
            case __NR_kill:
            case __NR_tkill:
            case __NR_tgkill:
                log_file->info("Sending signal {} to process/thread", evt.args[1]);
                break;
            case __NR_ptrace:
                log_file->info("Ptrace call with request {}", evt.args[0]);
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
                if (evt.filename[0] != '\0')
                {
                    log_file->info("File operation: {} on file: {}", evt.syscall, evt.filename);
                }
                break;
            case __NR_close:
                log_file->info("Closing file descriptor: {}", evt.args[0]);
                break;
            case __NR_read:
            case __NR_write:
                log_file->info("{} operation on fd {}, {} bytes",
                               (evt.syscall_nr == __NR_read) ? "Read" : "Write",
                               evt.args[0], evt.args[2]);
                break;
            case __NR_mount:
                log_file->info("Mounting filesystem");
                break;
            case __NR_umount2:
                log_file->info("Unmounting filesystem");
                break;

                // 네트워크 관련
            case __NR_socket:
                log_file->info("Creating socket: domain {}, type {}, protocol {}",
                               evt.args[0], evt.args[1], evt.args[2]);
                break;
            case __NR_connect:
                log_file->info("Connecting to socket");
                break;
            case __NR_accept:
                log_file->info("Accepting connection on socket");
                break;
            case __NR_bind:
                log_file->info("Binding socket");
                break;
            case __NR_listen:
                log_file->info("Listening on socket");
                break;
            case __NR_sendto:
            case __NR_recvfrom:
                log_file->info("{} on socket {}, {} bytes",
                               (evt.syscall_nr == __NR_sendto) ? "Sending" : "Receiving",
                               evt.args[0], evt.args[2]);
                break;
            case __NR_setsockopt:
            case __NR_getsockopt:
                log_file->info("{} socket option",
                               (evt.syscall_nr == __NR_setsockopt) ? "Setting" : "Getting");
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
                log_file->info("Changing process attributes: {}", evt.syscall);
                break;
            case __NR_prctl:
                log_file->info("Process control operation: {}", evt.args[0]);
                break;
            case __NR_setpriority:
            case __NR_sched_setscheduler:
            case __NR_sched_setparam:
            case __NR_sched_setaffinity:
                log_file->info("Changing process scheduling: {}", evt.syscall);
                break;
            case __NR_sched_yield:
                log_file->info("Yielding processor");
                break;
            case __NR_mprotect:
                log_file->info("mprotect called with addr={}, len={}, prot={}",
                               evt.args[0], evt.args[1], evt.args[2]);
                break;
            case __NR_mmap:
                log_file->info("mmap called with addr={}, len={}, prot={}, flags={}, fd={}, offset={}",
                               evt.args[0], evt.args[1], evt.args[2], evt.args[3], evt.args[4], evt.args[5]);
                break;
            case __NR_munmap:
                log_file->info("munmap called with addr={}, len={}", evt.args[0], evt.args[1]);
                break;
            default:
                log_file->info("Other system call: {}", evt.syscall);
                break;
            }
        }
        else
        {
            // 큐에 이벤트가 없을 경우 잠시 대기
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // 로그 파일 닫기 (spdlog는 자동으로 관리)
    spdlog::shutdown();
    std::cerr << "스레드 " << worker_id << " 종료됨.\n";
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
            spdlog::init_thread_pool(8192, 1); // 큐 사이즈와 스레드 수 설정
        }
        catch (const spdlog::spdlog_ex &ex)
        {
            std::cerr << "spdlog 초기화 실패: " << ex.what() << std::endl;
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

        init_syscall_map(skel);

        // 워커 스레드 풀 생성 (CPU 코어 수에 맞춤)
        const int num_workers = std::thread::hardware_concurrency() * 2;
        std::cout << "워커 스레드 수: " << num_workers << "\n";
        std::vector<std::thread> worker_threads;
        for (int i = 0; i < num_workers; ++i)
        {
            worker_threads.emplace_back(worker_thread_func, i);
        }

        // 테스트 이벤트 추가 (확인용)
        for (int i = 0; i < num_workers; ++i)
        {
            event test_event = {};
            test_event.cgroup_id = i + 1;
            test_event.syscall_nr = 999;
            event_queue.enqueue(test_event);
        }

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
        ringbuf_thread1.join();
        ringbuf_thread2.join();

        // 링버퍼 정리
        ring_buffer__free(rb1);
        ring_buffer__free(rb2);

        // 워커 스레드 종료 요청 및 정리
        stop_workers = true;
        // 각 워커 스레드를 깨우기 위해 더미 이벤트 추가
        for (int i = 0; i < num_workers; ++i)
        {
            event dummy_event = {};
            dummy_event.cgroup_id = 0;
            dummy_event.syscall_nr = 0;
            event_queue.enqueue(dummy_event);
        }
        for (auto &t : worker_threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }

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
