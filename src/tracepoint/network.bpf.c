#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define ALLOW 0
#define BLOCK 1
#define LOGGING 2

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // event_id
    __type(value, __u32); // mode
    __uint(max_entries, 10240);
} event_mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct event_key);
    __type(value, __u32);   // action
    __uint(max_entries, 10240);
} event_policy_map SEC(".maps");

struct event_key {
    __u64 ns_id;
    __u32 event_id;
    char argument[256];
};

struct current_task {
    __u32 pid;
    __u64 ns_id;
};

static __always_inline struct current_task get_task_struct() {
    struct current_task ct = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL) {
        bpf_printk("failed to get cur task\n");
        return ct;
    }

    ct.pid = bpf_get_current_pid_tgid() >> 32;
    ct.ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    return ct;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 0;

    __s32 domain = BPF_CORE_READ(ctx, args[0]);
    __s32 type = BPF_CORE_READ(ctx, args[1]);
    __s32 protocol = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        bpf_printk("watched value: %d\n", *watched);
        if (*watched == LOGGING) {
            bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d\n", ct.ns_id, ct.pid, domain, type, protocol);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 1;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit socket: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit socket: success, ns_id=%llu, pid=%u fd=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_sys_enter_socketpair(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 2;

    __s32 domain = BPF_CORE_READ(ctx, args[0]);
    __s32 type = BPF_CORE_READ(ctx, args[1]);
    __s32 protocol = BPF_CORE_READ(ctx, args[2]);
    void *sv_ptr = (void *)BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            __s32 sv[2];
            long err = bpf_probe_read_user(sv, sizeof(sv), sv_ptr);
            if (err == 0) {
                bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d, sv[0]=%d, sv[1]=%d\n", 
                        ct.ns_id, ct.pid, domain, type, protocol, sv[0], sv[1]);
            } else {
                bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d, failed to read sv\n", 
                        ct.ns_id, ct.pid, domain, type, protocol);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socketpair")
int trace_raw_sys_exit_socketpair(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 3;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit socketpair: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit socketpair: success, ns_id=%llu, pid=%u fd=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int trace_sys_enter_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 4;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 level = BPF_CORE_READ(ctx, args[1]);
    __s32 optname = BPF_CORE_READ(ctx, args[2]);
    void *optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    __s32 optlen = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 optval;
            long err = bpf_probe_read_user(&optval, sizeof(optval), optval_ptr);
            if (err == 0) {
                bpf_printk("Enter setsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, optval=%u, optlen=%d\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname, optval, optlen);
            } else {
                bpf_printk("Enter setsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, failed to read optval\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setsockopt")
int trace_sys_exit_setsockopt(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 5;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit setsockopt: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit setsockopt: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}