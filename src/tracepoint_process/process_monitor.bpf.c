// SPDX-License-Identifier: GPL-2.0
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SYSCALL_ENTRIES 256
#define TASK_COMM_LEN 16

struct event {
    u32 pid;
    u32 uid;
    u32 syscall_nr;
    char comm[TASK_COMM_LEN];
    char syscall[16];
};

// 시스템 호출 번호와 이름 매핑을 위한 맵을 정의합니다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SYSCALL_ENTRIES);
    __type(key, u32);
    __type(value, char[16]);
} syscall_map SEC(".maps");

// 유저 공간으로 이벤트를 전달하기 위한 퍼퓸 이벤트 맵을 정의합니다.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// eBPF 프로그램 섹션 정의
SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 시스템 호출 번호를 가져옵니다.
    u32 syscall_nr = ctx->args[1];

    // 모니터링 대상 시스템 호출인지 확인합니다.
    char *syscall_name = bpf_map_lookup_elem(&syscall_map, &syscall_nr);
    if (!syscall_name)
        return 0; // 모니터링 대상이 아니면 반환

    // 현재 프로세스의 PID와 UID를 가져옵니다.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 프로세스 이름을 가져옵니다.
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 이벤트 구조체를 채웁니다.
    struct event event = {};
    event.pid = pid;
    event.uid = uid;
    event.syscall_nr = syscall_nr;
    __builtin_memcpy(&event.comm, comm, sizeof(event.comm));
    __builtin_memcpy(&event.syscall, syscall_name, sizeof(event.syscall));

    // 이벤트를 유저 공간으로 전달합니다.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
