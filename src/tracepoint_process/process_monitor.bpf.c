// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

// 시스템 콜 번호 정의
// Todo: memcmp를 사용하지 않고 비교하려면 아래 내용을 아키텍쳐 별로 정의해야함 
#ifndef __NR_execve
#define __NR_execve 59  // x86_64 아키텍처의 execve 시스템 콜 번호
#endif

#define TASK_COMM_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, char[16]);
} syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// 현재 프로세스의 PID를 저장할 맵
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} current_pid SEC(".maps");

// memcmp 함수 직접 구현
static inline int my_memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

static __always_inline __u64 get_cgroup_id() {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return 0;
    }

    int mem_cgrp_id = memory_cgrp_id;

    __u64 cgroup_id = BPF_CORE_READ(cur_tsk, cgroups, subsys[mem_cgrp_id], cgroup, kn, id);
    bpf_printk("cgroup_id: %llu\n", cgroup_id);

    return cgroup_id;
}

static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }

    int cgrp_id = memory_cgrp_id;


    // failed when use BPF_PROBE_READ
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    // bpf_printk("name: %s\n", name);
    if (bpf_probe_read_kernel_str(buf, sz, name) < 0) {
        bpf_printk("failed to get kernfs node name: %s\n", buf);
        return -1;
    }
    bpf_printk("cgroup name: %s\n", buf);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 현재 프로세스의 PID 확인
    u32 key = 0;
    u32 *current_pid_ptr = bpf_map_lookup_elem(&current_pid, &key);
    if (current_pid_ptr && *current_pid_ptr == pid) {
        // 현재 프로세스의 시스템 콜이면 무시
        return 0;
    }

    u64 syscall_nr = ctx->id;
    
    // 시스템 콜 맵에서 해당 시스템 콜 번호가 있는지 확인
    char *syscall_name = bpf_map_lookup_elem(&syscall_map, &syscall_nr);
    if (!syscall_name) {
        // 프로세스 관련 시스템 콜이 아니면 무시
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->tid = tid;
    e->ppid = ppid;
    e->uid = uid;
    e->syscall_nr = syscall_nr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(&e->syscall, syscall_name, sizeof(e->syscall));

    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    // execve 시��템 콜인 경우 filename과 argv 읽기
    // if (syscall_nr == __NR_execve)
    if (syscall_name && my_memcmp(syscall_name, "execve", 6) == 0) {
        const char *filename_ptr = (const char *)ctx->args[0];
        bpf_probe_read_str(e->filename, sizeof(e->filename), filename_ptr);

        const char **argv = (const char **)ctx->args[1];
        for (int i = 0; i < MAX_ARGS; i++) {
            const char *arg;
            bpf_probe_read(&arg, sizeof(arg), &argv[i]);
            if (!arg)
                break;
            bpf_probe_read_str(e->argv[i], sizeof(e->argv[i]), arg);
        }
    } else {
        e->filename[0] = '\0';
        for (int i = 0; i < MAX_ARGS; i++) {
            e->argv[i][0] = '\0';
        }
    }

    // // cgroup 이름 가져오기
    char cgroup_name[MAX_CGROUP_NAME_LEN] = {0};
    if (get_cgroup_name(cgroup_name, sizeof(cgroup_name)) == 0) {
        __builtin_memcpy(e->cgroup_name, cgroup_name, sizeof(e->cgroup_name));
    } else {
        __builtin_memcpy(e->cgroup_name, "Unknown", 8);
    }

    // cgroup id 가져오기
    __u64 cgroup_id = get_cgroup_id();
    e->cgroup_id = cgroup_id;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";