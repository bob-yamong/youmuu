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
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"
#include "container_info.h"
#include "syscall_list.h"

// concurrentqueue 헤더 포함
#include "../../concurrentqueue/concurrentqueue.h"

// concurrentqueue 정의 (Lock-Free Queue)
moodycamel::ConcurrentQueue<event> event_queue;

// 작업 스레드 종료 플래그
bool stop_workers = false;
struct process_monitor_bpf *skel;
std::atomic<bool> ringbuf_thread_running(true);
static bool exiting = false;

// 링버퍼 핸들러1
static int handle_event1(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event*>(data);
    // 디버그 메시지
    std::cerr << "handle_event1 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    // 큐에 이벤트 enqueue
    event_queue.enqueue(*e);
    return 0;
}

// 링버퍼 핸들러2
static int handle_event2(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event*>(data);
    // 디버그 메시지
    std::cerr << "handle_event2 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    // 큐에 이벤트 enqueue
    event_queue.enqueue(*e);
    return 0;
}

// 링버퍼 소비 스레드 함수
void ringbuf_thread_func(struct ring_buffer *rb) {
    while (ringbuf_thread_running) {
        int err = ring_buffer__poll(rb, 100); // 100ms 타임아웃
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << "\n";
            break;
        }
    }
}

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

// 시그널 핸들러
static void sig_handler(int sig)
{
    exiting = true;
    stop_workers = true;
    ringbuf_thread_running = false;
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
        struct ring_buffer *rb1 = ring_buffer__new(bpf_map__fd(skel->maps.events_1), handle_event1, NULL, NULL);
        struct ring_buffer *rb2 = ring_buffer__new(bpf_map__fd(skel->maps.events_2), handle_event2, NULL, NULL);
        if (!rb1 || !rb2) {
            std::cerr << "Failed to create ring buffer\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }
        
        // 링버퍼 읽기 스레드 생성
        std::thread ringbuf_thread1(ringbuf_thread_func, rb1);
        std::thread ringbuf_thread2(ringbuf_thread_func, rb2);

        // 메인 루프
        while (!exiting) {
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
