// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "event.h"

#define TASK_COMM_LEN 16

// 시스템 호출 번호와 이름 매핑을 위한 맵을 정의합니다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, char[16]);
} syscall_map SEC(".maps");

// 유저 공간으로 이벤트를 전달하기 위한 링 버퍼 맵을 정의합니다.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB 링 버퍼
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
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->uid = uid;
    e->syscall_nr = syscall_nr;
    __builtin_memcpy(&e->comm, comm, sizeof(e->comm));
    __builtin_memcpy(&e->syscall, syscall_name, sizeof(e->syscall));

    // 이벤트를 유저 공간으로 전달합니다.
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
