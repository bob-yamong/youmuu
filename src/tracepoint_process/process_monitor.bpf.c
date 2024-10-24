#define __KERNEL__
#include "vmlinux.h"
#undef __KERNEL__
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>
#include "event.h"

typedef unsigned int u32;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, char[16]);
} syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 28); // 128MB
} events_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 28); // 128MB
} events_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} container_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} container_cgroup_id SEC(".maps");

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


static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }

    int cgrp_id = memory_cgrp_id;


    // failed when use BPF_PROBE_READ
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    if (bpf_probe_read_kernel_str(buf, sz, name) < 0) {
        bpf_printk("failed to get kernfs node name: %s\n", buf);
        return -1;
    }

    return 0;
}

static __always_inline int should_monitor(u32 ppid, u64 cgroup_id) {
    u32 *monitored;

    monitored = bpf_map_lookup_elem(&container_cgroup_id, &cgroup_id);
    if (monitored)
        return 1;
    
    monitored = bpf_map_lookup_elem(&container_pids, &ppid);
    if (monitored)
        return 1;
    
    return 0;
}

// 파일 이름을 첫 번째 인자로 가지는 시스템 콜 번호를 저장하는 배열
static const int syscalls_with_filename_1[] = {
    __NR_open, __NR_unlink, __NR_unlinkat, __NR_execve, __NR_execveat,
    __NR_mkdir, __NR_mkdirat, __NR_rmdir, __NR_renameat, __NR_renameat2,
    __NR_symlink, __NR_symlinkat, __NR_link, __NR_linkat,
    __NR_chmod, __NR_fchmodat, __NR_chown, __NR_lchown, __NR_fchownat,
    __NR_access, __NR_faccessat, __NR_stat, __NR_lstat, __NR_newfstatat,
    __NR_truncate, __NR_readlink, __NR_readlinkat
};

// 파일 이름을 두 번째 인자로 가지는 시스템 콜 번호를 저장하는 배열
static const int syscalls_with_filename_2[] = {
     __NR_openat, 
};

// 시스템 콜이 파일 이름을 첫 번째 인자로 가지는지 확인하는 함수
static inline int has_filename_arg(int syscall_nr) {
    for (int i = 0; i < sizeof(syscalls_with_filename_1) / sizeof(syscalls_with_filename_1[0]); i++) {
        if (syscall_nr == syscalls_with_filename_1[i]) {
            return 1;
        }
    }
    for (int i = 0; i < sizeof(syscalls_with_filename_2) / sizeof(syscalls_with_filename_2[0]); i++) {
        if (syscall_nr == syscalls_with_filename_2[i]) {
            return 2;
        }
    }
    return 0;
}

// debug
__u64 cnt = 0;
__u32 rb_flag = 0;

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 uid = bpf_get_current_uid_gid();
    u32 event_err_flag = 0;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    

    // cgroup id 가져오기
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    u64 *existing_cgroup_id = bpf_map_lookup_elem(&container_cgroup_id, &cgroup_id);
    if (!existing_cgroup_id) {
        bpf_map_update_elem(&container_cgroup_id, &cgroup_id, &cgroup_id, BPF_ANY);
    }

    u64 syscall_nr = ctx->id;
    

    // 시스템 콜 맵에서 해당 시스템 콜 번호가 있는지 확인
    char *syscall_name = bpf_map_lookup_elem(&syscall_map, &syscall_nr);
    if (!syscall_name) {
        return 0;
    }


    struct event *e;
    cnt++;
    // e = bpf_ringbuf_reserve(&events_1, sizeof(*e), 0);
    // if (!e)
    //     e = bpf_ringbuf_reserve(&events_2, sizeof(*e), 0);

    // if (!e)
    //     return 0;

    if(rb_flag == 0){
        e = bpf_ringbuf_reserve(&events_1, sizeof(*e), 0);
        rb_flag = 1;
    } else {
        e = bpf_ringbuf_reserve(&events_2, sizeof(*e), 0);
        rb_flag = 0;
    }

    if(!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->cnt = cnt;
    e->pid = pid;
    e->tid = tid;
    e->ppid = ppid;
    e->uid = uid;
    e->syscall_nr = syscall_nr;
    e->cgroup_id = cgroup_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(&e->syscall, syscall_name, sizeof(e->syscall));

    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    // 파일 이름을 첫 번째 인자로 가지는 시스템 콜 처리
    int filename_arg = has_filename_arg(syscall_nr);
    if (filename_arg == 1) {
        const char *filename_ptr = (const char *)ctx->args[0];
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    } else if (filename_arg == 2) {
        const char *filename_ptr = (const char *)ctx->args[1];
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    if (syscall_nr == __NR_execve || syscall_nr == __NR_execveat) {
        const char **argv = (const char **)ctx->args[1];
        for (int i = 0; i < MAX_ARGS; i++) {
            const char *arg;
            bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
            if (!arg)
                break;
            bpf_probe_read_user_str(e->argv[i], sizeof(e->argv[i]), arg);
        }
    } else {
        for (int i = 0; i < MAX_ARGS; i++) {
            e->argv[i][0] = '\0';
        }
    }

    // cgroup 이름 가져오기
    char cgroup_name[MAX_CGROUP_NAME_LEN] = {0};
    if (get_cgroup_name(cgroup_name, sizeof(cgroup_name)) == 0) {
        __builtin_memcpy(e->cgroup_name, cgroup_name, sizeof(e->cgroup_name));
    } else {
        __builtin_memcpy(e->cgroup_name, "Unknown", 8);
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";