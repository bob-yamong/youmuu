#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[256]);
    __uint(max_entries, 10);
} buf_map SEC(".maps");

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
    __u32 event_id = 1;

    __s32 domain = BPF_CORE_READ(ctx, args[0]);
    __s32 type = BPF_CORE_READ(ctx, args[1]);
    __s32 protocol = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d\n", 
            ct.ns_id, ct.pid, domain, type, protocol);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 2;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit socket: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit socket: success, ns_id=%llu, pid=%u fd=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_sys_enter_socketpair(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 3;

    __s32 domain = BPF_CORE_READ(ctx, args[0]);
    __s32 type = BPF_CORE_READ(ctx, args[1]);
    __s32 protocol = BPF_CORE_READ(ctx, args[2]);
    void *sv_ptr = (void *)BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
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
    __u32 event_id = 4;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit socketpair: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit socketpair: success, ns_id=%llu, pid=%u fd=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int trace_sys_enter_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 5;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 level = BPF_CORE_READ(ctx, args[1]);
    __s32 optname = BPF_CORE_READ(ctx, args[2]);
    void *optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    __s32 optlen = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
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
    __u32 event_id = 6;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit setsockopt: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit setsockopt: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int trace_sys_enter_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 7;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 level = BPF_CORE_READ(ctx, args[1]);
    __s32 optname = BPF_CORE_READ(ctx, args[2]);
    void *optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    __u32 *optlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 optval;
            __u32 optlen;
            long err = bpf_probe_read_user(&optval, sizeof(optval), optval_ptr);
            bpf_probe_read_user(&optlen, sizeof(optlen), optlen_ptr);
            if (err == 0) {
                bpf_printk("Enter getsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, optval=%u, optlen=%d\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname, optval, optlen);
            } else {
                bpf_printk("Enter getsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, failed to read optval\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockopt")
int trace_sys_exit_getsockopt(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 8;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getsockopt: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getsockopt: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname") 
int trace_sys_enter_getsockname(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 9;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 *addrlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            __u32 addrlen;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            bpf_probe_read_user(&addrlen, sizeof(addrlen), addrlen_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter getsockname: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter getsockname: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockname")
int trace_sys_exit_getsockname(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 10;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getsockname: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getsockname: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int trace_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 11;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 *addrlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            __u32 addrlen;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            bpf_probe_read_user(&addrlen, sizeof(addrlen), addrlen_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter getpeername: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter getpeername: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getpeername")
int trace_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 12;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getpeername: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getpeername: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 13;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter bind: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter bind: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int trace_sys_exit_bind(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 14;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit bind: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit bind: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_sys_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 15;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 backlog = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter listen: ns_id=%llu, pid=%u sockfd=%d, backlog=%d\n", 
                    ct.ns_id, ct.pid, sockfd, backlog);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int trace_sys_exit_listen(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 16;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit listen: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit listen: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 17;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 *addrlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            __u32 addrlen;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            bpf_probe_read_user(&addrlen, sizeof(addrlen), addrlen_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter accept: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter accept: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 18;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit accept: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit accept: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 19;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 *addrlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            __u32 addrlen;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            bpf_probe_read_user(&addrlen, sizeof(addrlen), addrlen_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter accept4: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u, flags=%d\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen, flags);
            } else {
                bpf_printk("Enter accept4: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 20;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit accept4: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit accept4: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 21;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter connect: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter connect: ns_id=%llu, pid=%u sockfd=%d, failed to read addr\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 22;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit connect: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit connect: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_sys_enter_shutdown(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 23;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 how = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter shutdown: ns_id=%llu, pid=%u sockfd=%d, how=%d\n", 
                    ct.ns_id, ct.pid, sockfd, how);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shutdown")
int trace_sys_exit_shutdown(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 24;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit shutdown: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit shutdown: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 25;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);
    void *src_addr_ptr = (void *)BPF_CORE_READ(ctx, args[4]);
    __u32 *addrlen_ptr = (__u32 *)BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in src_addr;
            __u32 addrlen;
            long err = bpf_probe_read_user(&src_addr, sizeof(src_addr), src_addr_ptr);
            bpf_probe_read_user(&addrlen, sizeof(addrlen), addrlen_ptr);
            if (err == 0) {
                __u32 ip = src_addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(src_addr.sin_port);
                bpf_printk("Enter recvfrom: ns_id=%llu, pid=%u sockfd=%d, len=%u, flags=%u, src_addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, len, flags, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter recvfrom: ns_id=%llu, pid=%u sockfd=%d, len=%u, flags=%u, failed to read src_addr\n", 
                        ct.ns_id, ct.pid, sockfd, len, flags);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 26;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit recvfrom: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit recvfrom: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 27;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msg_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct msghdr msg;
            long err = bpf_probe_read_user(&msg, sizeof(msg), msg_ptr);
            if (err == 0) {
                bpf_printk("Enter recvmsg: ns_id=%llu, pid=%u sockfd=%d, flags=%u\n", 
                        ct.ns_id, ct.pid, sockfd, flags);
            } else {
                bpf_printk("Enter recvmsg: ns_id=%llu, pid=%u sockfd=%d, failed to read msg\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 28;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit recvmsg: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit recvmsg: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int trace_sys_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 29;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msgvec_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 vlen = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);
    void *timeout_ptr = (void *)BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct mmsghdr msgvec;
            long err = bpf_probe_read_user(&msgvec, sizeof(msgvec), msgvec_ptr);
            if (err == 0) {
                bpf_printk("Enter recvmmsg: ns_id=%llu, pid=%u sockfd=%d, vlen=%u, flags=%u\n", 
                        ct.ns_id, ct.pid, sockfd, vlen, flags);
            } else {
                bpf_printk("Enter recvmmsg: ns_id=%llu, pid=%u sockfd=%d, failed to read msgvec\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int trace_sys_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 30;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit recvmmsg: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit recvmmsg: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 31;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *buf_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 len = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);
    void *dest_addr_ptr = (void *)BPF_CORE_READ(ctx, args[4]);
    __u32 addrlen = BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in dest_addr;
            long err = bpf_probe_read_user(&dest_addr, sizeof(dest_addr), dest_addr_ptr);
            if (err == 0) {
                __u32 ip = dest_addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(dest_addr.sin_port);
                bpf_printk("Enter sendto: ns_id=%llu, pid=%u sockfd=%d, len=%u, flags=%u, dest_addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, len, flags, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter sendto: ns_id=%llu, pid=%u sockfd=%d, len=%u, flags=%u, failed to read dest_addr\n", 
                        ct.ns_id, ct.pid, sockfd, len, flags);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 32;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit sendto: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit sendto: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 33;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msg_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct msghdr msg;
            long err = bpf_probe_read_user(&msg, sizeof(msg), msg_ptr);
            if (err == 0) {
                bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, flags=%u\n", 
                        ct.ns_id, ct.pid, sockfd, flags);
            } else {
                bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, failed to read msg\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 34;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit sendmsg: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit sendmsg: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 35;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msgvec_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 vlen = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct mmsghdr msgvec;
            long err = bpf_probe_read_user(&msgvec, sizeof(msgvec), msgvec_ptr);
            if (err == 0) {
                bpf_printk("Enter sendmmsg: ns_id=%llu, pid=%u sockfd=%d, vlen=%u, flags=%u\n", 
                        ct.ns_id, ct.pid, sockfd, vlen, flags);
            } else {
                bpf_printk("Enter sendmmsg: ns_id=%llu, pid=%u sockfd=%d, failed to read msgvec\n", 
                        ct.ns_id, ct.pid, sockfd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int trace_sys_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 36;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit sendmmsg: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit sendmmsg: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int trace_sys_enter_sethostname(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 37;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *hostname = bpf_map_lookup_elem(&buf_map, &key);
            if (hostname) {
                long err = bpf_probe_read_user(hostname, sizeof(hostname), name);
                if (err == 0) {
                    bpf_printk("Enter sethostname: ns_id=%llu, pid=%u, hostname=%s, len=%u\n", 
                            ct.ns_id, ct.pid, hostname, len);
                } else {
                    bpf_printk("Enter sethostname: ns_id=%llu, pid=%u, failed to read hostname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sethostname")
int trace_sys_exit_sethostname(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 38;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit sethostname: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit sethostname: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int trace_sys_enter_setdomainname(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 39;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            char domainname[64];
            long err = bpf_probe_read_user(domainname, sizeof(domainname), name);
            if (err == 0) {
                bpf_printk("Enter setdomainname: ns_id=%llu, pid=%u, domainname=%s, len=%u\n", 
                        ct.ns_id, ct.pid, domainname, len);
            } else {
                bpf_printk("Enter setdomainname: ns_id=%llu, pid=%u, failed to read domainname\n", 
                        ct.ns_id, ct.pid);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setdomainname")
int trace_sys_exit_setdomainname(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 40;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();
    
    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit setdomainname: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit setdomainname: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 41;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter close: ns_id=%llu, pid=%u, fd=%d\n", 
                    ct.ns_id, ct.pid, fd);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 42;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit close: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit close: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_sys_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 43;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 mode = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter creat: ns_id=%llu, pid=%u, pathname=%s, mode=%u\n", 
                            ct.ns_id, ct.pid, path, mode);
                } else {
                    bpf_printk("Enter creat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_sys_exit_creat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 44;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit creat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit creat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 45;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 flags = BPF_CORE_READ(ctx, args[1]);
    __u32 mode = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter open: ns_id=%llu, pid=%u, pathname=%s, flags=%u, mode=%u\n", 
                            ct.ns_id, ct.pid, path, flags, mode);
                } else {
                    bpf_printk("Enter open: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_sys_exit_open(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 46;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit open: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit open: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 47;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);
    __u32 mode = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter openat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, flags=%u, mode=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path, flags, mode);
                } else {
                    bpf_printk("Enter openat: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname\n", 
                            ct.ns_id, ct.pid, dirfd);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 48;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit openat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit openat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 49;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);
    __u32 mode = BPF_CORE_READ(ctx, args[3]);
    __u32 resolve = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter openat2: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, flags=%u, mode=%u, resolve=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path, flags, mode, resolve);
                } else {
                    bpf_printk("Enter openat2: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname\n", 
                            ct.ns_id, ct.pid, dirfd);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 50;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit openat2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit openat2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int trace_sys_enter_name_to_handle_at(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 51;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    void *handle_ptr = (void *)BPF_CORE_READ(ctx, args[2]);
    __u32 mount_id = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    struct file_handle handle;
                    long err = bpf_probe_read_user(&handle, sizeof(handle), handle_ptr);
                    if (err == 0) {
                        bpf_printk("Enter name_to_handle_at: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, mount_id=%u, flags=%u\n", 
                                ct.ns_id, ct.pid, dirfd, path, mount_id, flags);
                    } else {
                        bpf_printk("Enter name_to_handle_at: ns_id=%llu, pid=%u, dirfd=%d, failed to read handle\n", 
                                ct.ns_id, ct.pid, dirfd);
                    }
                } else {
                    bpf_printk("Enter name_to_handle_at: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname\n", 
                            ct.ns_id, ct.pid, dirfd);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_name_to_handle_at")
int trace_sys_exit_name_to_handle_at(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 52;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit name_to_handle_at: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit name_to_handle_at: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int trace_sys_enter_open_by_handle_at(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 53;

    __s32 mount_fd = BPF_CORE_READ(ctx, args[0]);
    void *handle_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            struct file_handle handle;
            long err = bpf_probe_read_user(&handle, sizeof(handle), handle_ptr);
            if (err == 0) {
                bpf_printk("Enter open_by_handle_at: ns_id=%llu, pid=%u, mount_fd=%d, flags=%u\n", 
                        ct.ns_id, ct.pid, mount_fd, flags);
            } else {
                bpf_printk("Enter open_by_handle_at: ns_id=%llu, pid=%u, mount_fd=%d, failed to read handle\n", 
                        ct.ns_id, ct.pid, mount_fd);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open_by_handle_at")
int trace_sys_exit_open_by_handle_at(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 54;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit open_by_handle_at: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit open_by_handle_at: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 55;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 flags = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            char memfd_name[64];
            long err = bpf_probe_read_user(memfd_name, sizeof(memfd_name), name);
            if (err == 0) {
                bpf_printk("Enter memfd_create: ns_id=%llu, pid=%u, name=%s, flags=%u\n", 
                        ct.ns_id, ct.pid, memfd_name, flags);
            } else {
                bpf_printk("Enter memfd_create: ns_id=%llu, pid=%u, failed to read name\n", 
                        ct.ns_id, ct.pid);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int trace_sys_exit_memfd_create(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 56;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit memfd_create: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit memfd_create: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 57;

    void *addr = (void *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);
    __u32 prot = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);
    __s32 fd = BPF_CORE_READ(ctx, args[4]);
    __u32 offset = BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter mmap: ns_id=%llu, pid=%u, addr=%p, len=%u, prot=%u, flags=%u, fd=%d, offset=%u\n", 
                    ct.ns_id, ct.pid, addr, len, prot, flags, fd, offset);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 58;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mmap: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mmap: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_sys_enter_munmap(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 59;

    void *addr = (void *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter munmap: ns_id=%llu, pid=%u, addr=%p, len=%u\n", 
                    ct.ns_id, ct.pid, addr, len);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int trace_sys_exit_munmap(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 60;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit munmap: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit munmap: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 61;

    void *addr = (void *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);
    __u32 prot = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter mprotect: ns_id=%llu, pid=%u, addr=%p, len=%u, prot=%u\n", 
                    ct.ns_id, ct.pid, addr, len, prot);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int trace_sys_exit_mprotect(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 62;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mprotect: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mprotect: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")
int trace_sys_enter_pkey_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 63;

    void *addr = (void *)BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[1]);
    __u32 prot = BPF_CORE_READ(ctx, args[2]);
    __u32 pkey = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter pkey_mprotect: ns_id=%llu, pid=%u, addr=%p, len=%u, prot=%u, pkey=%u\n", 
                    ct.ns_id, ct.pid, addr, len, prot, pkey);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pkey_mprotect")
int trace_sys_exit_pkey_mprotect(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 64;
    __s64 ret = BPF_CORE_READ(ctx, ret);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit pkey_mprotect: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit pkey_mprotect: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_sys_enter_mknod(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 65;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 mode = BPF_CORE_READ(ctx, args[1]);
    __u32 dev = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter mknod: ns_id=%llu, pid=%u, pathname=%s, mode=%u, dev=%u\n", 
                            ct.ns_id, ct.pid, path, mode, dev);
                } else {
                    bpf_printk("Enter mknod: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknod")
int trace_sys_exit_mknod(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 66;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mknod: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mknod: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_sys_enter_mknodat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 67;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 mode = BPF_CORE_READ(ctx, args[2]);
    __u32 dev = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter mknodat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, mode=%u, dev=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path, mode, dev);
                } else {
                    bpf_printk("Enter mknodat: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname\n", 
                            ct.ns_id, ct.pid, dirfd);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknodat")
int trace_sys_exit_mknodat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 68;
    __s64 ret = BPF_CORE_READ(ctx, ret);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mknodat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mknodat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 69;

    char *oldpath = (char *)BPF_CORE_READ(ctx, args[0]);
    char *newpath = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 old_key = 0;
            __u32 new_key = 1;
            char *old_path = bpf_map_lookup_elem(&buf_map, &old_key);
            char *new_path = bpf_map_lookup_elem(&buf_map, &new_key);
            if (old_path && new_path) {
                long old_err = bpf_probe_read_user(old_path, sizeof(char) * 256, oldpath);
                long new_err = bpf_probe_read_user(new_path, sizeof(char) * 256, newpath);
                if (old_err == 0 && new_err == 0) {
                    bpf_printk("Enter rename: ns_id=%llu, pid=%u, oldpath=%s, newpath=%s\n", 
                            ct.ns_id, ct.pid, old_path, new_path);
                } else {
                    bpf_printk("Enter rename: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_sys_exit_rename(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 70;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit rename: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit rename: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 71;

    __s32 olddirfd = BPF_CORE_READ(ctx, args[0]);
    char *oldpath = (char *)BPF_CORE_READ(ctx, args[1]);
    __s32 newdirfd = BPF_CORE_READ(ctx, args[2]);
    char *newpath = (char *)BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 old_key = 0;
            __u32 new_key = 1;
            char *old_path = bpf_map_lookup_elem(&buf_map, &old_key);
            char *new_path = bpf_map_lookup_elem(&buf_map, &new_key);
            if (old_path && new_path) {
                long old_err = bpf_probe_read_user(old_path, sizeof(char) * 256, oldpath);
                long new_err = bpf_probe_read_user(new_path, sizeof(char) * 256, newpath);
                if (old_err == 0 && new_err == 0) {
                    bpf_printk("Enter renameat: ns_id=%llu, pid=%u, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u\n", 
                            ct.ns_id, ct.pid, olddirfd, old_path, newdirfd, new_path, flags);
                } else {
                    bpf_printk("Enter renameat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int trace_sys_exit_renameat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 72;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit renameat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit renameat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 73;

    __s32 olddirfd = BPF_CORE_READ(ctx, args[0]);
    char *oldpath = (char *)BPF_CORE_READ(ctx, args[1]);
    __s32 newdirfd = BPF_CORE_READ(ctx, args[2]);
    char *newpath = (char *)BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 old_key = 0;
            __u32 new_key = 1;
            char *old_path = bpf_map_lookup_elem(&buf_map, &old_key);
            char *new_path = bpf_map_lookup_elem(&buf_map, &new_key);
            if (old_path && new_path) {
                long old_err = bpf_probe_read_user(old_path, sizeof(char) * 256, oldpath);
                long new_err = bpf_probe_read_user(new_path, sizeof(char) * 256, newpath);
                if (old_err == 0 && new_err == 0) {
                    bpf_printk("Enter renameat2: ns_id=%llu, pid=%u, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u\n", 
                            ct.ns_id, ct.pid, olddirfd, old_path, newdirfd, new_path, flags);
                } else {
                    bpf_printk("Enter renameat2: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 74;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit renameat2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit renameat2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_sys_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 75;

    char *path = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 length = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, path);
                if (err == 0) {
                    bpf_printk("Enter truncate: ns_id=%llu, pid=%u, path=%s, length=%u\n", 
                            ct.ns_id, ct.pid, path, length);
                } else {
                    bpf_printk("Enter truncate: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int trace_sys_exit_truncate(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 76;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit truncate: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit truncate: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_sys_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 77;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u32 length = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter ftruncate: ns_id=%llu, pid=%u, fd=%d, length=%u\n", 
                    ct.ns_id, ct.pid, fd, length);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")
int trace_sys_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 78;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit ftruncate: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit ftruncate: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int trace_sys_enter_fallocate(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 79;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u32 mode = BPF_CORE_READ(ctx, args[1]);
    __u32 offset = BPF_CORE_READ(ctx, args[2]);
    __u32 len = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fallocate: ns_id=%llu, pid=%u, fd=%d, mode=%u, offset=%u, len=%u\n", 
                    ct.ns_id, ct.pid, fd, mode, offset, len);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fallocate")
int trace_sys_exit_fallocate(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 80;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit fallocate: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fallocate: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_sys_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 81;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 mode = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter mkdir: ns_id=%llu, pid=%u, pathname=%s, mode=%u\n", 
                            ct.ns_id, ct.pid, path, mode);
                } else {
                    bpf_printk("Enter mkdir: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_sys_exit_mkdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 82;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mkdir: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mkdir: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 83;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 mode = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter mkdirat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, mode=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path, mode);
                } else {
                    bpf_printk("Enter mkdirat: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname\n", 
                            ct.ns_id, ct.pid, dirfd);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int trace_sys_exit_mkdirat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 84;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit mkdirat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit mkdirat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 85;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path = bpf_map_lookup_elem(&buf_map, &key);
            if (path) {
                long err = bpf_probe_read_user(path, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter rmdir: ns_id=%llu, pid=%u, pathname=%s\n", 
                            ct.ns_id, ct.pid, path);
                } else {
                    bpf_printk("Enter rmdir: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int trace_sys_exit_rmdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 86;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit rmdir: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit rmdir: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int trace_sys_enter_getcwd(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 87;

    char *buf = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 size = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter getcwd: ns_id=%llu, pid=%u, buf_addr=%p, size=%u\n", 
                    ct.ns_id, ct.pid, buf, size);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getcwd")
int trace_sys_exit_getcwd(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 88;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getcwd: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getcwd: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 89;

    char *path = (char *)BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &key);
            if (path_buf) {
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, path);
                if (err == 0) {
                    bpf_printk("Enter chdir: ns_id=%llu, pid=%u, path=%s\n", 
                            ct.ns_id, ct.pid, path_buf);
                } else {
                    bpf_printk("Enter chdir: ns_id=%llu, pid=%u, failed to read path\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_sys_exit_chdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 90;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit chdir: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit chdir: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_sys_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 91;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fchdir: ns_id=%llu, pid=%u, fd=%d\n", 
                    ct.ns_id, ct.pid, fd);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int trace_sys_exit_fchdir(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 92;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit fchdir: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fchdir: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_sys_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 93;

    char *path = (char *)BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &key);
            if (path_buf) {
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, path);
                if (err == 0) {
                    bpf_printk("Enter chroot: ns_id=%llu, pid=%u, path=%s\n", 
                            ct.ns_id, ct.pid, path_buf);
                } else {
                    bpf_printk("Enter chroot: ns_id=%llu, pid=%u, failed to read path\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chroot")
int trace_sys_exit_chroot(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 94;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit chroot: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit chroot: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int trace_sys_enter_getdents(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 95;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    void *dirent = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 count = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter getdents: ns_id=%llu, pid=%u, fd=%d, dirent_addr=%p, count=%u\n", 
                    ct.ns_id, ct.pid, fd, dirent, count);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int trace_sys_exit_getdents(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 96;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getdents: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getdents: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 97;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    void *dirent = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 count = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter getdents64: ns_id=%llu, pid=%u, fd=%d, dirent_addr=%p, count=%u\n", 
                    ct.ns_id, ct.pid, fd, dirent, count);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 98;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit getdents64: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getdents64: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_sys_enter_link(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 99;

    char *oldpath = (char *)BPF_CORE_READ(ctx, args[0]);
    char *newpath = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 old_key = 0;
            __u32 new_key = 1;
            char *old_path = bpf_map_lookup_elem(&buf_map, &old_key);
            char *new_path = bpf_map_lookup_elem(&buf_map, &new_key);
            if (old_path && new_path) {
                long old_err = bpf_probe_read_user(old_path, sizeof(char) * 256, oldpath);
                long new_err = bpf_probe_read_user(new_path, sizeof(char) * 256, newpath);
                if (old_err == 0 && new_err == 0) {
                    bpf_printk("Enter link: ns_id=%llu, pid=%u, oldpath=%s, newpath=%s\n", 
                            ct.ns_id, ct.pid, old_path, new_path);
                } else {
                    bpf_printk("Enter link: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_sys_exit_link(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 100;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit link: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit link: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_sys_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 101;

    __s32 olddirfd = BPF_CORE_READ(ctx, args[0]);
    char *oldpath = (char *)BPF_CORE_READ(ctx, args[1]);
    __s32 newdirfd = BPF_CORE_READ(ctx, args[2]);
    char *newpath = (char *)BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 old_key = 0;
            __u32 new_key = 1;
            char *old_path = bpf_map_lookup_elem(&buf_map, &old_key);
            char *new_path = bpf_map_lookup_elem(&buf_map, &new_key);
            if (old_path && new_path) {
                long old_err = bpf_probe_read_user(old_path, sizeof(char) * 256, oldpath);
                long new_err = bpf_probe_read_user(new_path, sizeof(char) * 256, newpath);
                if (old_err == 0 && new_err == 0) {
                    bpf_printk("Enter linkat: ns_id=%llu, pid=%u, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%u\n", 
                            ct.ns_id, ct.pid, olddirfd, old_path, newdirfd, new_path, flags);
                } else {
                    bpf_printk("Enter linkat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int trace_sys_exit_linkat(struct trace_event_raw_sys_exit *ctx) {
    __u32 event_id = 102;
    __s64 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit linkat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit linkat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}