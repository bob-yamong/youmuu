#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "structs.h"
#include "map.h"

#define ALLOW 0
#define BLOCK 1
#define LOGGING 2
#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

__u64 count = 0;

static __always_inline struct current_task get_task_struct() {
    struct current_task ct = {0};

    ct.timestamp = bpf_ktime_get_ns();
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    if (cur_task == NULL) {
        bpf_printk("failed to get cur task\n");
        return ct;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    ct.cgroup_id = bpf_get_current_cgroup_id();
    ct.ns_id = BPF_CORE_READ(cur_task, nsproxy, pid_ns_for_children, ns.inum);
    ct.ppid = BPF_CORE_READ(cur_task, real_parent, tgid);
    ct.pid = pid_tgid >> 32;
    ct.tid = (__u32)pid_tgid;
    ct.uid = uid_gid;
    ct.gid = uid_gid >> 32;

    return ct;
}

static __always_inline struct event_t *ring_buffer(__s64 event_id, struct current_task ct) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return NULL;
    } else {
        count ++;
        e->event_id = event_id;
        e->task = ct;
        e->task.count = count;
    }
    return e;
}

static __always_inline struct map_key get_map_key(struct current_task *ct) {
    struct map_key key = {
        .pid = ct->pid,
        .tid = ct->tid,
        .ns_id = ct->ns_id
    };
    return key;
}

static __always_inline bool should_log_event(__u32 ns_id, __s64 event_id) {
    struct event_key event_key = {
        .ns_id = ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    return (watched && *watched == LOGGING);
}

static __always_inline struct event_t* handle_enter_event(__s64 event_id) {
    struct current_task ct = get_task_struct();
    if (!should_log_event(ct.ns_id, event_id)) 
        return NULL;

    struct event_t *e = ring_buffer(event_id, ct);
    if (!e)
        return NULL;

    e->is_enter = true;
    return e;
}

static __always_inline struct event_t* handle_exit_event(__s64 event_id) {
    struct current_task ct = get_task_struct();

    if (!should_log_event(ct.ns_id, event_id)) 
        return NULL;

    struct event_t *e = ring_buffer(event_id, ct);
    if (!e)
        return NULL;

    e->is_enter = false;
    return e;
}

static inline void init_socket_fields(struct event_t *e) {
    e->ip = 0;
    e->port = 0;
    e->addr_family = 0;
    e->is_valid = false;
    e->is_null = false;
}

static inline bool read_sockaddr(struct event_t *e, void *addr_ptr) {
    if (!addr_ptr) 
        return false;
    
    __u16 family;
    if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0)
        return false;

    e->addr_family = family;

    if (family == AF_INET) {
        struct sockaddr_in addr;
        if (bpf_probe_read_user(&addr, sizeof(addr), addr_ptr) == 0) {
            e->ip = addr.sin_addr.s_addr;
            e->port = bpf_ntohs(addr.sin_port);
            e->is_valid = true;
            return true;
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6;
        if (bpf_probe_read_user(&addr6, sizeof(addr6), addr_ptr) == 0) {
            bpf_probe_read_user(&e->ipv6_addr, sizeof(e->ipv6_addr), &addr6.sin6_addr);
            e->port = bpf_ntohs(addr6.sin6_port);
            e->is_valid = true;
            return true;
        }
    }
    return false;
}

// 네트워크 관련 이벤트
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    bpf_printk("event_id=%lld\n", BPF_CORE_READ(ctx, id));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_sys_enter_socketpair(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    void *sv_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    
    bpf_map_update_elem(&socketpair_args_map, &key, &sv_ptr, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socketpair")
int trace_sys_exit_socketpair(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    e->arg_s32[0] = -1;
    e->arg_s32[1] = -1;
    e->is_valid = false;

    if (ret >= 0) {
        __u64 *sv_ptr = bpf_map_lookup_elem(&socketpair_args_map, &key);
        if (sv_ptr) {
            __s32 sv[2];
            if (bpf_probe_read_user(sv, sizeof(sv), (void *)*sv_ptr) == 0) {
                e->arg_s32[0] = sv[0];
                e->arg_s32[1] = sv[1];
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    
cleanup:
    bpf_map_delete_elem(&socketpair_args_map, &ct);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int trace_sys_enter_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[3] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    void *optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    if (optval_ptr) {
        __u32 optval;
        if (bpf_probe_read_user(&optval, sizeof(optval), optval_ptr) == 0) {
            e->arg_u32[0] = optval;
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setsockopt")
int trace_sys_exit_setsockopt(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int trace_sys_enter_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct getsockopt_args args = {
        .optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]),
        .optlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[4])
    };

    bpf_map_update_elem(&getsockopt_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockopt")
int trace_sys_exit_getsockopt(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct getsockopt_args *args = bpf_map_lookup_elem(&getsockopt_args_map, &key);
        if (args) {
            __u32 optlen;
            if (bpf_probe_read_user(&optlen, sizeof(optlen), args->optlen_ptr) == 0) {
                e->arg_u32[1] = optlen;
                if (optlen <= sizeof(e->arg_u32[0])) {
                    if (bpf_probe_read_user(&e->arg_u32[0], optlen, args->optval_ptr) == 0) {
                        e->is_valid = true;
                    }
                }
            }
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    
cleanup:
    bpf_map_delete_elem(&getsockopt_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname") 
int trace_sys_enter_getsockname(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct sock_addr_args args = {
        .addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]),
        .addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2])
    };

    bpf_map_update_elem(&getsockname_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockname")
int trace_sys_exit_getsockname(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct sock_addr_args *args = bpf_map_lookup_elem(&getsockname_args_map, &key);
        if (args && args->addr_ptr) {
            read_sockaddr(e, args->addr_ptr);
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&getsockname_args_map, &key);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int trace_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct sock_addr_args args = {
        .addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]),
        .addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2])
    };

    bpf_map_update_elem(&getpeername_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
    

SEC("tracepoint/syscalls/sys_exit_getpeername")
int trace_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct sock_addr_args *args = bpf_map_lookup_elem(&getpeername_args_map, &key);
        if (args && args->addr_ptr) {
            read_sockaddr(e, args->addr_ptr);
        }
    }
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&getpeername_args_map, &key);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    init_socket_fields(e);

    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    read_sockaddr(e, addr_ptr);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int trace_sys_exit_bind(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_sys_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int trace_sys_exit_listen(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct sock_addr_args args = {
        .addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]),
        .addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2])
    };

    bpf_map_update_elem(&accept_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct sock_addr_args *args = bpf_map_lookup_elem(&accept_args_map, &key);
        if (args && args->addr_ptr) {
            read_sockaddr(e, args->addr_ptr);
        } else {
            e->is_null = true;
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&accept_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct sock_addr_args args = {
        .addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]),
        .addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2])
    };

    bpf_map_update_elem(&accept4_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct sock_addr_args *args = bpf_map_lookup_elem(&accept4_args_map, &key);
        if (args && args->addr_ptr) {
            read_sockaddr(e, args->addr_ptr);
        } else {
            e->is_null = true;
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&accept_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    init_socket_fields(e);

    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    read_sockaddr(e, addr_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_sys_enter_shutdown(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shutdown")
int trace_sys_exit_shutdown(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct sock_addr_args args = {
        .addr_ptr = (void *)BPF_CORE_READ(ctx, args[4]),
        .addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[5])
    };

    bpf_map_update_elem(&recvfrom_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct sock_addr_args *args = bpf_map_lookup_elem(&recvfrom_args_map, &key);
        if (args && args->addr_ptr) {
            read_sockaddr(e, args->addr_ptr);
        } else {
            e->is_null = true;
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&recvfrom_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct msg_args args = {
        .msg_ptr = (struct msghdr *)BPF_CORE_READ(ctx, args[1])
    };

    bpf_map_update_elem(&recvmsg_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    init_socket_fields(e);

    if (ret >= 0) {
        struct msg_args *args = bpf_map_lookup_elem(&recvmsg_args_map, &key);
        if (args) {
            struct msghdr msg;
            if (bpf_probe_read_user(&msg, sizeof(msg), args->msg_ptr) == 0) {
                read_sockaddr(e, msg.msg_name);
            }
        }
    }
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&recvmsg_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int trace_sys_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int trace_sys_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    init_socket_fields(e);

    void *dest_addr_ptr = (void *)BPF_CORE_READ(ctx, args[4]);
    read_sockaddr(e, dest_addr_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    init_socket_fields(e);

    void *msg_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    if (msg_ptr) {
        struct msghdr msg;
        if (bpf_probe_read_user(&msg, sizeof(msg), msg_ptr) != 0)
            goto submit;
        read_sockaddr(e, msg.msg_name);
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int trace_sys_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int trace_sys_enter_sethostname(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    if (name) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name) >= 0) {
            e->is_valid = true;
        }   
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sethostname")
int trace_sys_exit_sethostname(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int trace_sys_enter_setdomainname(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    if (name) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name) >= 0) {
            e->is_valid = true;
        }   
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setdomainname")
int trace_sys_exit_setdomainname(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")  // 설정 변경 탐지 모니터링 필요?
int trace_sys_enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int trace_sys_exit_ioctl(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int trace_sys_enter_poll(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct pollfd *fds_ptr = (struct pollfd *)BPF_CORE_READ(ctx, args[0]);
    struct poll_args args = {
        .fds = fds_ptr
    };

    bpf_map_update_elem(&poll_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    if (fds_ptr) {
        struct pollfd pfd;
        if (bpf_probe_read_user(&pfd, sizeof(pfd), fds_ptr) == 0) {
            e->arg_s32[1] = pfd.fd;
            e->arg_s32[2] = pfd.events;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_poll")
int trace_sys_exit_poll(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct poll_args *args = bpf_map_lookup_elem(&poll_args_map, &key);
        if (args && args->fds) {
            struct pollfd pfd;
            if (bpf_probe_read_user(&pfd, sizeof(pfd), args->fds) == 0) {
                e->arg_s32[0] = pfd.revents;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&poll_args_map, &key);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int trace_sys_enter_ppoll(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct pollfd *fds_ptr = (struct pollfd *)BPF_CORE_READ(ctx, args[0]);
    struct poll_args args = {
        .fds = fds_ptr
    };

    bpf_map_update_elem(&poll_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    void *tsp = (void *)BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    if (fds_ptr) {
        struct pollfd pfd;
        if (bpf_probe_read_user(&pfd, sizeof(pfd), fds_ptr) == 0) {
            e->arg_s32[1] = pfd.fd;
            e->arg_s32[2] = pfd.events;
            e->is_valid = true;
        }
    }

    if (tsp) {
        struct timespec_args ts;
        if (bpf_probe_read_user(&ts, sizeof(ts), tsp) == 0) {
            e->arg_u64[1] = ts.tv_sec;
            e->arg_u64[2] = ts.tv_nsec;
        }
    } else {
        e->arg_u64[1] = 999999999;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ppoll")
int trace_sys_exit_ppoll(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct poll_args *args = bpf_map_lookup_elem(&poll_args_map, &key);
        if (args && args->fds) {
            struct pollfd pfd;
            if (bpf_probe_read_user(&pfd, sizeof(pfd), args->fds) == 0) {
                e->arg_s32[0] = pfd.revents;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&poll_args_map, &key);    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create")
int trace_sys_enter_epoll_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_create")
int trace_sys_exit_epoll_create(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int trace_sys_enter_epoll_create1(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_create1")
int trace_sys_exit_epoll_create1(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int trace_sys_enter_epoll_ctl(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    
    struct epoll_event *event_ptr = (struct epoll_event *)BPF_CORE_READ(ctx, args[3]);
    if (event_ptr) {
        struct epoll_event event;
        if (bpf_probe_read_user(&event, sizeof(event), event_ptr) == 0) {
            e->arg_u32[0] = event.events;
            e->arg_u64[0] = event.data;
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_ctl")
int trace_sys_exit_epoll_ctl(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int trace_sys_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct epoll_args args = {
        .events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1])
    };

    bpf_map_update_elem(&epoll_wait_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int trace_sys_exit_epoll_wait(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;
    
    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct epoll_args *args = bpf_map_lookup_elem(&epoll_wait_args_map, &key);
        if (args && args->events) {
            struct epoll_event events;
            if (bpf_probe_read_user(&events, sizeof(events), args->events) == 0) {
                e->arg_u32[0] = events.events;
                e->arg_u64[0] = events.data;
                e->is_valid = true;
            }
        }
    }
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&epoll_wait_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int trace_sys_enter_epoll_pwait(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct epoll_args args = {
        .events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1])
    };

    bpf_map_update_elem(&epoll_pwait_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int trace_sys_exit_epoll_pwait(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;
    
    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct epoll_args *args = bpf_map_lookup_elem(&epoll_pwait_args_map, &key);
        if (args && args->events) {
            struct epoll_event events;
            if (bpf_probe_read_user(&events, sizeof(events), args->events) == 0) {
                e->arg_u32[0] = events.events;
                e->arg_u64[0] = events.data;
                e->is_valid = true;
            }
        }
    }
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&epoll_pwait_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int trace_sys_enter_epoll_pwait2(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct epoll_args args = {
        .events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1])
    };

    bpf_map_update_elem(&epoll_pwait2_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    void *timeout = (void *)BPF_CORE_READ(ctx, args[3]);
    
    if (timeout) {
        struct timespec_args ts;
        if (bpf_probe_read_user(&ts, sizeof(ts), timeout) == 0) {
            e->arg_u64[0] = ts.tv_sec;
            e->arg_u64[1] = ts.tv_nsec;
        }
    } else {
        e->arg_u64[0] = 999999999;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait2")
int trace_sys_exit_epoll_pwait2(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        goto cleanup;
    
    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct epoll_args *args = bpf_map_lookup_elem(&epoll_pwait2_args_map, &key);
        if (args && args->events) {
            struct epoll_event events;
            if (bpf_probe_read_user(&events, sizeof(events), args->events) == 0) {
                e->arg_u32[0] = events.events;
                e->arg_u64[0] = events.data;
                e->is_valid = true;
            }
        }
    }
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&epoll_pwait2_args_map, &key);
    return 0;
}

// file system related tracepoints
SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_sys_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_sys_exit_creat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_sys_exit_open(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    void *how_ptr = (void *)BPF_CORE_READ(ctx, args[2]);
    if (pathname_ptr && how_ptr) {
        struct open_how how;
        if (bpf_probe_read_user(&how, sizeof(how), how_ptr) == 0) {
            e->arg_u64[1] = how.flags;
            e->arg_u64[2] = how.mode;
            e->arg_u64[3] = how.resolve;
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int trace_sys_enter_name_to_handle_at(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    __s32 flags = BPF_CORE_READ(ctx, args[4]);

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    void *handle_ptr = (void *)BPF_CORE_READ(ctx, args[2]);
    __u64 *mount_id_ptr = (__u64 *)BPF_CORE_READ(ctx, args[3]);

    if (pathname_ptr && handle_ptr && mount_id_ptr) {
        __s32 mount_id;
        e->arg_s32[2] = bpf_probe_read_user(&mount_id, sizeof(mount_id), mount_id_ptr);
        struct file_handle handle;
        if (bpf_probe_read_user(&handle, sizeof(handle), handle_ptr) == 0) {
            e->arg_u32[0] = handle.handle_bytes;
            e->arg_s32[3] = handle.handle_type;
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_name_to_handle_at")
int trace_sys_exit_name_to_handle_at(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int trace_sys_enter_open_by_handle_at(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    void *handle_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    if (handle_ptr) {
        struct file_handle handle;
        if (bpf_probe_read_user(&handle, sizeof(handle), handle_ptr) == 0) {
            e->arg_u32[0] = handle.handle_bytes;
            e->arg_s32[2] = handle.handle_type;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open_by_handle_at")
int trace_sys_exit_open_by_handle_at(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int trace_sys_exit_memfd_create(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_sys_enter_mknod(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknod")
int trace_sys_exit_mknod(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_sys_enter_mknodat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknodat")
int trace_sys_exit_mknodat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *oldpath_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *newpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (oldpath_ptr && newpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), oldpath_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), newpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_sys_exit_rename(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *oldpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    char *newpath_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    if (oldpath_ptr && newpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), oldpath_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), newpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int trace_sys_exit_renameat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *oldpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    char *newpath_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    if (oldpath_ptr && newpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), oldpath_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), newpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_sys_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (path_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int trace_sys_exit_truncate(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_sys_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")
int trace_sys_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_fallocate")
int trace_sys_enter_fallocate(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[1] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fallocate")
int trace_sys_exit_fallocate(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_sys_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_sys_exit_mkdir(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int trace_sys_exit_mkdirat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int trace_sys_exit_rmdir(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int trace_sys_enter_getcwd(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getcwd")
int trace_sys_exit_getcwd(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (path_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_sys_exit_chdir(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_sys_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int trace_sys_exit_fchdir(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_sys_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (path_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chroot")
int trace_sys_exit_chroot(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_sys_enter_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *new_root_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *put_old_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (new_root_ptr && put_old_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), new_root_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), put_old_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pivot_root")
int trace_sys_exit_pivot_root(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int trace_sys_enter_getdents(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct getdents_args args = {
        .dirents = (void *)BPF_CORE_READ(ctx, args[1]),
    };

    bpf_map_update_elem(&getdents_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int trace_sys_exit_getdents(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct getdents_args *args = bpf_map_lookup_elem(&getdents_args_map, &key);
        if (args && args->dirents) {
            struct linux_dirent dirents;
            if (bpf_probe_read_user(&dirents, sizeof(dirents), args->dirents) == 0) {
                e->arg_u64[0] = dirents.d_ino;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&getsockopt_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct getdents_args args = {
        .dirents = (void *)BPF_CORE_READ(ctx, args[1]),
    };

    bpf_map_update_elem(&getdents64_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;

    if (ret >= 0) {
        struct getdents_args *args = bpf_map_lookup_elem(&getdents64_args_map, &key);
        if (args && args->dirents) {
            struct linux_dirent64 dirents;
            if (bpf_probe_read_user(&dirents, sizeof(dirents), args->dirents) == 0) {
                e->arg_u64[0] = dirents.d_ino;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&getsockopt_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_sys_enter_link(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *oldpath_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *newpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (oldpath_ptr && newpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), oldpath_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), newpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_sys_exit_link(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_sys_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;
    
    char *oldpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    char *newpath_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    if (oldpath_ptr && newpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), oldpath_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), newpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int trace_sys_exit_linkat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_sys_enter_symlink(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *target_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *linkpath_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (target_ptr && linkpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), target_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), linkpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_sys_exit_symlink(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_sys_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *target_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *linkpath_ptr = (char *)BPF_CORE_READ(ctx, args[2]);
    if (target_ptr && linkpath_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), target_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), linkpath_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlinkat")
int trace_sys_exit_symlinkat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_sys_exit_unlink(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int trace_sys_enter_readlink(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (path_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readlink")
int trace_sys_exit_readlink(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int trace_sys_enter_readlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (path_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readlinkat")
int trace_sys_exit_readlinkat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int trace_sys_enter_umask(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_umask")
int trace_sys_exit_umask(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_newstat")
// int trace_sys_enter_stat(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->is_valid = false;

//     char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
//     if (pathname_ptr) {
//         if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
//             e->is_valid = true;
//         }
//     }
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_newstat")
// int trace_sys_exit_stat(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_newlstat")
// int trace_sys_enter_lstat(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->is_valid = false;

//     char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
//     if (pathname_ptr) {
//         if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
//             e->is_valid = true;
//         }
//     }
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_newlstat")
// int trace_sys_exit_lstat(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_newfstat")
// int trace_sys_enter_fstat(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_newfstat")
// int trace_sys_exit_fstat(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_newfstatat")
// int trace_sys_enter_fstatat(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
//     e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
//     e->is_valid = false;

//     char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
//     if (pathname_ptr) {
//         if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
//             e->is_valid = true;
//         }
//     }

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_newfstatat")
// int trace_sys_exit_fstatat(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_statx")
// int trace_sys_enter_statx(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
//     e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
//     e->arg_u32[0] = BPF_CORE_READ(ctx, args[3]);
//     e->is_valid = false;
    
//     char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
//     if (pathname_ptr) {
//         if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
//             e->is_valid = true;
//         }
//     }

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_statx")
// int trace_sys_exit_statx(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_statfs")
// int trace_sys_enter_statfs(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->is_valid = false;
    
//     char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
//     if (path_ptr) {
//         if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), path_ptr) >= 0) {
//             e->is_valid = true;
//         }
//     }

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_statfs")
// int trace_sys_exit_statfs(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_fstatfs")
// int trace_sys_enter_fstatfs(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;
    
//     e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_fstatfs")
// int trace_sys_exit_fstatfs(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_sys_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int trace_sys_exit_chmod(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int trace_sys_exit_fchmod(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int trace_sys_exit_fchmodat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_sys_enter_chown(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chown")
int trace_sys_exit_chown(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int trace_sys_enter_lchown(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lchown")
int trace_sys_exit_lchown(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_sys_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int trace_sys_exit_fchown(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_sys_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int trace_sys_exit_fchownat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utime")
int trace_sys_enter_utime(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->is_valid = false;
    e->is_null = true;

    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    struct utimbuf *times_ptr = (struct utimbuf *)BPF_CORE_READ(ctx, args[1]);
    if (filename_ptr) {
        if (times_ptr) {
            struct utimbuf time_values;
            if (bpf_probe_read_user(&time_values, sizeof(time_values), times_ptr) == 0 &&
                bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), filename_ptr) >= 0) {
                e->arg_u64[0] = time_values.actime;
                e->arg_u64[1] = time_values.modtime;
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), filename_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_utime")
int trace_sys_exit_utime(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimes")
int trace_sys_enter_utimes(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->is_valid = false;
    e->is_null = true;

    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    struct __kernel_old_timeval *utimes_ptr = (struct __kernel_old_timeval *)BPF_CORE_READ(ctx, args[1]);
    if (filename_ptr) {
        if (utimes_ptr) {
            struct __kernel_old_timeval time_values[2];
            if (bpf_probe_read_user(&time_values, sizeof(time_values), utimes_ptr) == 0 &&
                bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), filename_ptr) >= 0) {
                e->arg_u32[0] = time_values[0].tv_sec;
                e->arg_s32[0] = time_values[0].tv_usec;
                e->arg_u32[1] = time_values[1].tv_sec;
                e->arg_s32[1] = time_values[1].tv_usec;
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), filename_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_utimes")
int trace_sys_exit_utimes(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futimesat")
int trace_sys_enter_futimesat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->is_valid = false;
    e->is_null = true;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    struct __kernel_old_timeval *utimes_ptr = (struct __kernel_old_timeval *)BPF_CORE_READ(ctx, args[2]);
    if (pathname_ptr) {
        if (utimes_ptr) {
            struct __kernel_old_timeval time_values[2];
            if (bpf_probe_read_user(&time_values, sizeof(time_values), utimes_ptr) == 0 &&
                bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->arg_u32[0] = time_values[0].tv_sec;
                e->arg_s32[0] = time_values[0].tv_usec;
                e->arg_u32[1] = time_values[1].tv_sec;
                e->arg_s32[1] = time_values[1].tv_usec;
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futimesat")
int trace_sys_exit_futimesat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int trace_sys_enter_utimensat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;
    e->is_null = true;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    struct timespec64 *utimes_ptr = (struct timespec64 *)BPF_CORE_READ(ctx, args[2]);
    if (pathname_ptr) {
        if (utimes_ptr) {
            struct timespec64 time_values[2];
            if (bpf_probe_read_user(&time_values, sizeof(time_values), utimes_ptr) == 0 &&
                bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->arg_u64[0] = time_values[0].tv_sec;
                e->arg_u64[1] = time_values[0].tv_nsec;
                e->arg_u64[2] = time_values[1].tv_sec;
                e->arg_u64[3] = time_values[1].tv_nsec;
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_utimensat")
int trace_sys_exit_utimensat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int trace_sys_enter_access(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_access")
int trace_sys_exit_access(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int trace_sys_enter_faccessat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_faccessat")
int trace_sys_exit_faccessat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_sys_enter_setxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int trace_sys_exit_setxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int trace_sys_enter_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lsetxattr")
int trace_sys_exit_lsetxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int trace_sys_enter_fsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsetxattr")
int trace_sys_exit_fsetxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_sys_enter_getxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getxattr")
int trace_sys_exit_getxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int trace_sys_enter_lgetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lgetxattr")
int trace_sys_exit_lgetxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int trace_sys_enter_fgetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fgetxattr")
int trace_sys_exit_fgetxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int trace_sys_enter_listxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    e->is_null = true;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *list_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (list_ptr) {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
                bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), list_ptr) >= 0) {
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listxattr")
int trace_sys_exit_listxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int trace_sys_enter_llistxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    e->is_null = true;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *list_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (list_ptr) {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
                bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), list_ptr) >= 0) {
                e->is_valid = true;
                e->is_null = false;
            }
        } else {
            if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_llistxattr")
int trace_sys_exit_llistxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int trace_sys_enter_flistxattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    e->is_null = true;

    char *list_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (list_ptr) {
        e->is_null = false;
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), list_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flistxattr")
int trace_sys_exit_flistxattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int trace_sys_enter_removexattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_removexattr")
int trace_sys_exit_removexattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int trace_sys_enter_lremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr && name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lremovexattr")
int trace_sys_exit_lremovexattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int trace_sys_enter_fremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->is_valid = false;
    
    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (name_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), name_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fremovexattr")
int trace_sys_exit_fremovexattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_sys_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u64[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_sys_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_sys_enter_dup(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int trace_sys_exit_dup(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int trace_sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int trace_sys_enter_flock(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flock")
int trace_sys_exit_flock(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_sys_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int trace_sys_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int trace_sys_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int trace_sys_exit_readv(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int trace_sys_enter_preadv(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[3]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv")
int trace_sys_exit_preadv(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int trace_sys_enter_preadv2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[4]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv2")
int trace_sys_exit_preadv2(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int trace_sys_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev")
int trace_sys_exit_pwritev(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int trace_sys_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[4]);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev2")
int trace_sys_exit_pwritev2(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int trace_sys_enter_lseek(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int trace_sys_exit_lseek(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int trace_sys_enter_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile64")
int trace_sys_exit_sendfile64(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init")
int trace_sys_enter_inotify_init(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_init")
int trace_sys_exit_inotify_init(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int trace_sys_enter_inotify_init1(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_init1")
int trace_sys_exit_inotify_init1(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int trace_sys_enter_inotify_add_watch(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_add_watch")
int trace_sys_exit_inotify_add_watch(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int trace_sys_enter_inotify_rm_watch(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_rm_watch")
int trace_sys_exit_inotify_rm_watch(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int trace_sys_enter_fanotify_init(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fanotify_init")
int trace_sys_exit_fanotify_init(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int trace_sys_enter_fanotify_mark(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;
    e->is_null = true;
    
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[4]);
    if (pathname_ptr) {
        e->is_null = false;
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fanotify_mark")
int trace_sys_exit_fanotify_mark(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    char *source_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    char *target_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    char *filesystemtype_ptr = (char *)BPF_CORE_READ(ctx, args[2]);
    if (source_ptr && target_ptr && filesystemtype_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), source_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), target_ptr) >= 0 &&
            bpf_probe_read_user_str(e->filesystem_type, sizeof(e->filesystem_type), filesystemtype_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mount")
int trace_sys_exit_mount(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int trace_sys_enter_umount(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    char *target_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (target_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), target_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_umount")
int trace_sys_exit_umount(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int trace_sys_enter_move_mount(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *from_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    char *to_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    if (from_ptr && to_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), from_ptr) >= 0 &&
            bpf_probe_read_user_str(e->arg_str2, sizeof(e->arg_str2), to_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_move_mount")
int trace_sys_exit_move_mount(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone") 
int trace_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int trace_sys_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_sys_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    __u64 args_ptr = BPF_CORE_READ(ctx, args[0]);
    if (args_ptr) {
        struct clone_args cl_args;
        if (bpf_probe_read_user(&cl_args, sizeof(cl_args), (void *)args_ptr) ==0) {
            e->arg_u64[0] = cl_args.flags;
            e->arg_u64[1] = cl_args.stack;
            e->arg_u64[2] = cl_args.stack_size;
            e->arg_u64[3] = cl_args.cgroup;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int trace_sys_exit_clone3(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_sys_enter_fork(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fork")
int trace_sys_exit_fork(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_sys_enter_vfork(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int trace_sys_exit_vfork(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[4]);
    e->is_valid = false;

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    if (pathname_ptr) {
        if (bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), pathname_ptr) >= 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_sys_exit_execveat(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int trace_sys_enter_exit(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_exit")
int trace_sys_exit_exit(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_exit_group")
int trace_sys_exit_exit_group(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int trace_sys_enter_wait4(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[2]);
    e->is_valid = false;

    __s32 *status_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    if (status_ptr) {
        if (bpf_probe_read_user(&e->arg_s32[1], sizeof(e->arg_s32[1]), status_ptr) == 0) {
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_wait4")
int trace_sys_exit_wait4(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int trace_sys_enter_waitid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[3]);
    e->is_valid = false;

    __u64 *infop_ptr = (void *)BPF_CORE_READ(ctx, args[2]);
    if (infop_ptr) {
        siginfo_t info;
        if (bpf_probe_read_user(&e->arg_s32[2], sizeof(e->arg_s32[2]), infop_ptr) == 0) {
            e->arg_s32[2] = info.si_signo;
            e->arg_s32[3] = info.si_code;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_waitid")
int trace_sys_exit_waitid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_getpid")
// int trace_sys_enter_getpid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getpid")
// int trace_sys_exit_getpid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_getppid")
// int trace_sys_enter_getppid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getppid")
// int trace_sys_exit_getppid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_gettid")
// int trace_sys_enter_gettid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_gettid")
// int trace_sys_exit_gettid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_setsid")
int trace_sys_enter_setsid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setsid")
int trace_sys_exit_setsid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_getsid")
// int trace_sys_enter_getsid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;

//     e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getsid")
// int trace_sys_exit_getsid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_setpgid")
int trace_sys_enter_setpgid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setpgid")
int trace_sys_exit_setpgid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_getpgid")
// int trace_sys_enter_getpgid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e) 
//         return 0;

//     e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getpgid")
// int trace_sys_exit_getpgid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_getpgrp")
int trace_sys_enter_getpgrp(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e) 
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getpgrp")
int trace_sys_exit_getpgrp(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_sys_exit_setuid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_getuid")
// int trace_sys_enter_getuid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getuid")
// int trace_sys_exit_getuid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_sys_enter_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int trace_sys_exit_setgid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_getgid")
// int trace_sys_enter_getgid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getgid")
// int trace_sys_exit_getgid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int trace_sys_exit_setresuid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int trace_sys_enter_getresuid(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct resuid_args args = {
        .ruid = (__u64)(void *)BPF_CORE_READ(ctx, args[0]),
        .euid = (__u64)(void *)BPF_CORE_READ(ctx, args[1]),
        .suid = (__u64)(void *)BPF_CORE_READ(ctx, args[2]),
    };

    bpf_map_update_elem(&resuid_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getresuid")
int trace_sys_exit_getresuid(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;
    
    if (ret >= 0) {
        struct resuid_args *args = bpf_map_lookup_elem(&resuid_args_map, &key);
        if (args && args->ruid && args->euid && args->suid) {
            __u32 ruid, euid, suid;
            if (bpf_probe_read_user(&ruid, sizeof(ruid), (void *)args->ruid) == 0 &&
                bpf_probe_read_user(&euid, sizeof(euid), (void *)args->euid) == 0 &&
                bpf_probe_read_user(&suid, sizeof(suid), (void *)args->suid) == 0) {
                e->arg_u32[0] = ruid;
                e->arg_u32[1] = euid;
                e->arg_u32[2] = suid;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&resuid_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_sys_enter_setresgid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_u32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setresgid")
int trace_sys_exit_setresgid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int trace_sys_enter_getresgid(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    struct resgid_args args = {
        .rgid = (__u64)(void *)BPF_CORE_READ(ctx, args[0]),
        .egid = (__u64)(void *)BPF_CORE_READ(ctx, args[1]),
        .sgid = (__u64)(void *)BPF_CORE_READ(ctx, args[2]),
    };

    bpf_map_update_elem(&resgid_args_map, &key, &args, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getresgid")
int trace_sys_exit_getresgid(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;
    
    if (ret >= 0) {
        struct resgid_args *args = bpf_map_lookup_elem(&resgid_args_map, &key);
        if (args && args->rgid && args->egid && args->sgid) {
            __u32 rgid, egid, sgid;
            if (bpf_probe_read_user(&rgid, sizeof(rgid), (void *)args->rgid) == 0 &&
                bpf_probe_read_user(&egid, sizeof(egid), (void *)args->egid) == 0 &&
                bpf_probe_read_user(&sgid, sizeof(sgid), (void *)args->sgid) == 0) {
                e->arg_u32[0] = rgid;
                e->arg_u32[1] = egid;
                e->arg_u32[2] = sgid;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&resgid_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setreuid")
int trace_sys_exit_setreuid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_sys_enter_setregid(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setregid")
int trace_sys_exit_setregid(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_geteuid")
// int trace_sys_enter_geteuid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_geteuid")
// int trace_sys_exit_geteuid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_getegid")
// int trace_sys_enter_getegid(struct trace_event_raw_sys_enter *ctx) {
//     struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_getegid")
// int trace_sys_exit_getegid(struct trace_event_raw_sys_exit *ctx) {
//     struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
//     if (!e)
//         return 0;
    
//     e->ret = BPF_CORE_READ(ctx, ret);
    
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_setgroups")
int trace_sys_enter_setgroups(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setgroups")
int trace_sys_exit_setgroups(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int trace_sys_enter_getgroups(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getgroups")
int trace_sys_exit_getgroups(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_sys_enter_setns(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setns")
int trace_sys_exit_setns(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int trace_sys_enter_setrlimit(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->is_valid = false;

    void *rlim_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    if (rlim_ptr) {
        struct rlimit rlim;
        if (bpf_probe_read_user(&rlim, sizeof(rlim), rlim_ptr) == 0) {
            e->arg_u64[0] = rlim.rlim_cur;
            e->arg_u64[1] = rlim.rlim_max;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setrlimit")
int trace_sys_exit_setrlimit(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int trace_sys_enter_getrlimit(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    void *rlim_ptr = (void *)BPF_CORE_READ(ctx, args[1]);

    bpf_map_update_elem(&getrlimit_args_map, &key, &rlim_ptr, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getrlimit")
int trace_sys_exit_getrlimit(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;
    
    if (ret >= 0) {
        __u64 *rlim_ptr = bpf_map_lookup_elem(&getrlimit_args_map, &key);
        if (rlim_ptr) {
            struct rlimit rlim;
            if (bpf_probe_read_user(&rlim, sizeof(rlim), rlim_ptr) == 0) {
                e->arg_u64[0] = rlim.rlim_cur;
                e->arg_u64[1] = rlim.rlim_max;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&getrlimit_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int trace_sys_enter_prlimit(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_prlimit64")
int trace_sys_exit_prlimit(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int trace_sys_enter_getrusage(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getrusage")
int trace_sys_exit_getrusage(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int trace_sys_enter_sched_setattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_setattr")
int trace_sys_exit_sched_setattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int trace_sys_enter_sched_getattr(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[1] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u32[2] = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_getattr")
int trace_sys_exit_sched_getattr(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int trace_sys_enter_sched_setscheduler(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_setscheduler")
int trace_sys_exit_sched_setscheduler(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int trace_sys_enter_sched_getscheduler(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_getscheduler")
int trace_sys_exit_sched_getscheduler(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int trace_sys_enter_sched_setparam(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_setparam")
int trace_sys_exit_sched_setparam(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int trace_sys_enter_sched_getparam(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_getparam")
int trace_sys_exit_sched_getparam(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int trace_sys_enter_sched_setaffinity(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->is_valid = false;

    void *mask_ptr = (void *)BPF_CORE_READ(ctx, args[2]);
    if (mask_ptr) {
        __u64 mask;
        if (bpf_probe_read_user(&mask, sizeof(mask), mask_ptr) == 0) {
            e->arg_u64[1] = mask;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_setaffinity")
int trace_sys_exit_sched_setaffinity(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int trace_sys_enter_sched_getaffinity(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);
    void *mask_ptr = (void *)BPF_CORE_READ(ctx, args[2]);

    bpf_map_update_elem(&sched_getaffinity_args_map, &key, &mask_ptr, BPF_ANY);

    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
        
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_getaffinity")
int trace_sys_exit_sched_getaffinity(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = BPF_CORE_READ(ctx, ret);
    struct current_task ct = get_task_struct();
    struct map_key key = get_map_key(&ct);

    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        goto cleanup;

    e->ret = ret;
    e->is_valid = false;
    
    if (ret >= 0) {
        void *mask_ptr = bpf_map_lookup_elem(&sched_getaffinity_args_map, &key);
        if (mask_ptr) {
            __u64 mask;
            if (bpf_probe_read_user(&mask, sizeof(mask), mask_ptr) == 0) {
                e->arg_u64[1] = mask;
                e->is_valid = true;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&sched_getaffinity_args_map, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int trace_sys_enter_sched_get_priority_max(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_get_priority_max")
int trace_sys_exit_sched_get_priority_max(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int trace_sys_enter_sched_get_priority_min(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_get_priority_min")
int trace_sys_exit_sched_get_priority_min(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int trace_sys_enter_sched_rr_get_interval(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_rr_get_interval")
int trace_sys_exit_sched_rr_get_interval(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_yield")
int trace_sys_enter_sched_yield(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sched_yield")
int trace_sys_exit_sched_yield(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int trace_sys_enter_setpriority(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setpriority")
int trace_sys_exit_setpriority(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int trace_sys_enter_getpriority(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getpriority")
int trace_sys_exit_getpriority(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int trace_sys_enter_ioprio_set(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[2] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioprio_set")
int trace_sys_exit_ioprio_set(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int trace_sys_enter_ioprio_get(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_s32[1] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioprio_get")
int trace_sys_exit_ioprio_get(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_s32[3] = BPF_CORE_READ(ctx, args[3]);
    e->arg_s32[4] = BPF_CORE_READ(ctx, args[4]);
    e->arg_u64[1] = BPF_CORE_READ(ctx, args[5]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->arg_u64[0] = BPF_CORE_READ(ctx, args[1]);
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int trace_sys_exit_mprotect(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_sys_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->is_valid = false;
    
    void *header_ptr = (void *)BPF_CORE_READ(ctx, args[0]);
    void *data_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    if (header_ptr && data_ptr) {
        struct __user_cap_header_struct header;
        struct __user_cap_data_struct data;
        if (bpf_probe_read_user(&header, sizeof(header), header_ptr) == 0 &&
            bpf_probe_read_user(&data, sizeof(data), data_ptr) == 0) {
            e->arg_u32[0] = header.version;
            e->arg_u32[1] = header.pid;
            e->arg_u32[2] = data.effective;
            e->arg_u32[3] = data.permitted;
            e->arg_u32[4] = data.inheritable;
            e->is_valid = true;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_capset")
int trace_sys_exit_capset(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_s32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int trace_sys_exit_ptrace(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_sys_enter_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[1] = BPF_CORE_READ(ctx, args[4]);
    e->arg_u64[2] = BPF_CORE_READ(ctx, args[5]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_process_vm_readv")
int trace_sys_exit_process_vm_readv(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_sys_enter_process_vm_writev(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = handle_enter_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;
    
    e->arg_u32[0] = BPF_CORE_READ(ctx, args[0]);
    e->arg_u64[0] = BPF_CORE_READ(ctx, args[2]);
    e->arg_u64[1] = BPF_CORE_READ(ctx, args[4]);
    e->arg_u64[2] = BPF_CORE_READ(ctx, args[5]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_process_vm_writev")
int trace_sys_exit_process_vm_writev(struct trace_event_raw_sys_exit *ctx) {
    struct event_t *e = handle_exit_event(BPF_CORE_READ(ctx, id));
    if (!e)
        return 0;

    e->ret = BPF_CORE_READ(ctx, ret);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}