#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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
        if (*watched == LOGGING) {
            bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d\n", 
            ct.ns_id, ct.pid, domain, type, protocol);
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

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int trace_sys_enter_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 6;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 level = BPF_CORE_READ(ctx, args[1]);
    __s32 optname = BPF_CORE_READ(ctx, args[2]);
    void *optval_ptr = (void *)BPF_CORE_READ(ctx, args[3]);
    __s32 optlen_ptr = BPF_CORE_READ(ctx, args[4]);

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
                bpf_printk("Enter getsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, optval=%u, optlen=%d\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname, optval, optlen_ptr);
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
    __u32 event_id = 7;
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
                bpf_printk("Exit getsockopt: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getsockopt: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname") 
int trace_sys_enter_getsockname(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 8;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen_ptr = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter getsockname: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen_ptr);
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
    __u32 event_id = 9;
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
                bpf_printk("Exit getsockname: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getsockname: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int trace_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 10;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen_ptr = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter getpeername: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen_ptr);
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
    __u32 event_id = 11;
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
                bpf_printk("Exit getpeername: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getpeername: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 12;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
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
    __u32 event_id = 13;
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
                bpf_printk("Exit bind: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit bind: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_sys_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 14;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 backlog = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
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
    __u32 event_id = 15;
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
                bpf_printk("Exit listen: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit listen: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 16;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen_ptr = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter accept: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen_ptr);
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
    __u32 event_id = 17;
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
                bpf_printk("Exit accept: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit accept: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 18;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen_ptr = BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
    if (watched) {
        if (*watched == LOGGING) {
            struct sockaddr_in addr;
            long err = bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
            if (err == 0) {
                __u32 ip = addr.sin_addr.s_addr;
                __u16 port = bpf_ntohs(addr.sin_port);
                bpf_printk("Enter accept4: ns_id=%llu, pid=%u sockfd=%d, addr=%u.%u.%u.%u:%u, addrlen=%u, flags=%d\n", 
                        ct.ns_id, ct.pid, sockfd, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen_ptr, flags);
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
    __u32 event_id = 19;
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
                bpf_printk("Exit accept4: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit accept4: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 20;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 addrlen = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
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
    __u32 event_id = 21;
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
                bpf_printk("Exit connect: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit connect: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_sys_enter_shutdown(struct trace_event_raw_sys_enter *ctx) {
    __u32 event_id = 22;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __s32 how = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);
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
    __u32 event_id = 23;
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
                bpf_printk("Exit shutdown: failed, ns_id=%llu, pid=%u, error code: %ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit shutdown: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}