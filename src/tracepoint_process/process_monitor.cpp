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

#include <unordered_map>
#include <functional>

// #include <libpq-fe.h>
#include <iomanip>




// 작업 스레드 종료 플래그
std::atomic<bool> stop_workers(false);
struct process_monitor_bpf *skel;
std::atomic<bool> ringbuf_thread_running(true);
static std::atomic<bool> exiting(false);
int rb_cnt_1 = 0;
int rb_cnt_2 = 0;

// 글로벌 맵 정의: 시스템 콜 번호를 로그 처리 함수로 매핑
std::unordered_map<int, std::function<void(const struct event*)>> syscall_logger_map;

// 맵 기반 접근 방식을 사용하는 로깅 함수
void logging(const struct event *e){
    
}

// 링버퍼 핸들러
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    // 디버그 메시지
    rb_cnt_1++;
    const struct event *e = static_cast<const struct event *>(data);
    if (rb_cnt_1 % 100000 == 0){
        std::cout << "[" << rb_cnt_1 << "]handle_event 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    }

    // 로그 기록
    // logging(e);

    return 0;
}


// 링버퍼 소비 스레드 함수
void ringbuf_thread_func(struct ring_buffer *rb)
{
    while (ringbuf_thread_running.load(std::memory_order_relaxed))
    {
        int err = ring_buffer__poll(rb, -1);
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


        // 링버퍼 설정
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events_1), handle_event, NULL, NULL);
        if (!rb)
        {
            std::cerr << "Failed to create ring buffer\n";
            process_monitor_bpf__destroy(skel);
            return 1;
        }

        // 링버퍼 읽기 스레드 생성
        std::vector <std::thread> ringbuf_thread;
        ringbuf_thread.push_back(std::thread (ringbuf_thread_func, rb));
        // ringbuf_thread.push_back(std::thread (ringbuf_thread_func, rb));
        // ringbuf_thread.push_back(std::thread (ringbuf_thread_func, rb));
        // ringbuf_thread.push_back(std::thread (ringbuf_thread_func, rb));
        // 메인 루프
        while (!exiting.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // 링버퍼 읽기 스레드 종료 요청
        ringbuf_thread_running.store(false, std::memory_order_relaxed);
        for (auto &t : ringbuf_thread)
            t.join();

        // 링버퍼 정리
        ring_buffer__free(rb);

        // BPF 스켈레톤 정리
        process_monitor_bpf__destroy(skel);

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
