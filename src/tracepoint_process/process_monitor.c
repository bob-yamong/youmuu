// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"

#define MAX_SYSCALL_ENTRIES 256

static volatile bool exiting = false;

void handle_signal(int sig)
{
    exiting = true;
}

// 시스템 호출 맵 초기화 함수
void init_syscall_map(struct process_monitor_bpf *skel)
{
    // 모니터링할 시스템 호출 번호와 이름을 정의합니다.
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_execveat, "execveat" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_kill, "kill" },
        { __NR_tgkill, "tgkill" },
        { __NR_tkill, "tkill" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_ptrace, "ptrace" },
        // 필요에 따라 추가적인 시스템 호출을 추가할 수 있음
    };

    int size = sizeof(syscall_list) / sizeof(syscall_list[0]);
    for (int i = 0; i < size; i++) {
        int nr = syscall_list[i].nr;
        const char *name = syscall_list[i].name;
        bpf_map_update_elem(bpf_map__fd(skel->maps.syscall_map), &nr, name, BPF_ANY);
    }
}

// 링 버퍼 이벤트 처리 콜백 함수
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Process syscall: %s (pid=%d, uid=%d, comm=%s)\n",
           e->syscall, e->pid, e->uid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct process_monitor_bpf *skel;
    int err;

    // 시그널 처리기 설정
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // RLIMIT_MEMLOCK 증가
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    // eBPF 스켈레톤 로드 및 초기화
    skel = process_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton\n");
        return 1;
    }

    // 시스템 호출 맵 초기화
    init_syscall_map(skel);

    // eBPF 프로그램 어태치
    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        goto cleanup;
    }

    // 링 버퍼 설정
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Process monitoring started. Press Ctrl+C to exit.\n");

    // 이벤트 루프
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return -err;
}
