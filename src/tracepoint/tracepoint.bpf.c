#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "struct.h"
#include "map.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

__u64 count = 0;

static __always_inline struct current_task get_task_struct(__s32 event_id) {
    struct current_task ct = {0};

    ct.timestamp = bpf_ktime_get_ns();
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    if (cur_task == NULL) {
        bpf_printk("failed to get cur task\n");
        return ct;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    ct.event_id = event_id;
    ct.cgroup_id = bpf_get_current_cgroup_id();
    ct.pid_namespace = BPF_CORE_READ(cur_task, nsproxy, pid_ns_for_children, ns.inum);
    ct.mnt_namespace = BPF_CORE_READ(cur_task, nsproxy, mnt_ns, ns.inum);
    ct.ppid = BPF_CORE_READ(cur_task, real_parent, tgid);
    ct.pid = pid_tgid >> 32;
    ct.tid = (__u32)pid_tgid;
    ct.uid = uid_gid;
    ct.gid = uid_gid >> 32;
    bpf_get_current_comm(&ct.comm, sizeof(ct.comm));

    return ct;
}

static __always_inline struct event_t *ring_buffer(struct current_task ct) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return NULL;
    } else {
        count ++;
        e->task = ct;
        e->task.count = count;
    }
    return e;
}

static __always_inline struct map_key get_map_key(struct current_task *ct) {
    struct map_key key = {
        .pid = ct->pid,
        .tid = ct->tid,
        .pid_namespace = ct->pid_namespace
    };
    return key;
}

static __always_inline bool should_log_event(__u32 pid_namespace, __s32 event_id) {
    __s32 *syscall_list = bpf_map_lookup_elem(&syscall_array, &pid_namespace);
    if (!syscall_list)
        return false;

    // 배열 검색
    #pragma unroll
    for (int i = 0; i < 120; i++) {
        if (syscall_list[i] == event_id)
            return true;
        if (syscall_list[i] == -1)
            return false;
    }

    return false;
}

static __always_inline struct event_t* handle_enter_event(__s32 event_id) {
    struct current_task ct = get_task_struct(event_id);
    if (!should_log_event(ct.pid_namespace, ct.event_id)) 
        return NULL;

    struct event_t *e = ring_buffer(ct);
    if (!e)
        return NULL;

    e->is_enter = true;
    return e;
}

static __always_inline struct event_t* handle_exit_event(__s32 event_id) {
    struct current_task ct = get_task_struct(event_id);

    if (!should_log_event(ct.pid_namespace, event_id)) 
        return NULL;

    struct event_t *e = ring_buffer(ct);
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

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_sys_enter_socketpair(struct trace_event_raw_sys_enter *ctx) {
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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
    struct current_task ct = get_task_struct(BPF_CORE_READ(ctx, id));
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

//네트워크 스택 기반 tracepoint
// 패킷 전송 이벤트
SEC("tracepoint/net/net_dev_xmit")
int trace_net_dev_xmit(struct trace_event_raw_net_dev_xmit *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

    // 패킷 전송 정보 추적
    return process_packet(ctx, skb, true);
}

// 패킷 수신 이벤트
SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

    // 패킷 수신 정보 추적
    return process_packet(ctx, skb, false);
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


