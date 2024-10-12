#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "event.h"

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
    __s32 event_id;
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

// network events related tracepoints
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_SOCKET;

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
    __s32 event_id = SYS_EXIT_SOCKET;
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
    __s32 event_id = SYS_ENTER_SOCKETPAIR;

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
                bpf_printk("Enter socket: ns_id=%llu, pid=%u domain=%d, type=%d, protocol=%d, sv_ptr=%p (failed to read sv)\n", 
                        ct.ns_id, ct.pid, domain, type, protocol, sv_ptr);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socketpair")
int trace_raw_sys_exit_socketpair(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SOCKETPAIR;
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
    __s32 event_id = SYS_ENTER_SETSOCKOPT;

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
                bpf_printk("Enter setsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, optval_ptr=%p (failed to read optval), optlen=%d\n", 
                        ct.ns_id, ct.pid, sockfd, level, optname, optval_ptr, optlen);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setsockopt")
int trace_sys_exit_setsockopt(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SETSOCKOPT;
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
    __s32 event_id = SYS_ENTER_GETSOCKOPT;

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
            bpf_printk("Enter getsockopt: ns_id=%llu, pid=%u sockfd=%d, level=%d, optname=%d, optval_ptr=%p, optlen_ptr=%p\n", 
                    ct.ns_id, ct.pid, sockfd, level, optname, optval_ptr, optlen_ptr);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockopt")
int trace_sys_exit_getsockopt(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_GETSOCKOPT;
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
    __s32 event_id = SYS_ENTER_GETSOCKNAME;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u64 *addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter getsockname: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p, addrlen_ptr=%p\n", 
                    ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen_ptr);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getsockname")
int trace_sys_exit_getsockname(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_GETSOCKNAME;
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
    __s32 event_id = SYS_ENTER_GETPEERNAME;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u64 *addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter getpeername: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p, addrlen_ptr=%p\n", 
                    ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen_ptr);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getpeername")
int trace_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_GETPEERNAME;
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
    __s32 event_id = SYS_ENTER_BIND;

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
                bpf_printk("Enter bind: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p (failed to read addr), addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int trace_sys_exit_bind(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_BIND;
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
    __s32 event_id = SYS_ENTER_LISTEN;

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
    __s32 event_id = SYS_EXIT_LISTEN;
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
    __s32 event_id = SYS_ENTER_ACCEPT;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u64 *addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (addr_ptr == NULL || addrlen_ptr == NULL) {
                bpf_printk("Enter accept: ns_id=%llu, pid=%u sockfd=%d, client address not requested\n", 
                    ct.ns_id, ct.pid, sockfd);
            } else {
                bpf_printk("Enter accept: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p, addrlen_ptr=%p\n", 
                        ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen_ptr);
                return 0;
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_ACCEPT;
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
    __s32 event_id = SYS_ENTER_ACCEPT4;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *addr_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u64 *addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (addr_ptr == NULL || addrlen_ptr == NULL) {
                bpf_printk("Enter accept4: ns_id=%llu, pid=%u sockfd=%d, client address not requested\n", 
                    ct.ns_id, ct.pid, sockfd);
            } else {
                bpf_printk("Enter accept4: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p, addrlen_ptr=%p, flags=%d\n", 
                        ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen_ptr, flags);
                return 0;
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_ACCEPT4;
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
    __s32 event_id = SYS_ENTER_CONNECT;

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
                bpf_printk("Enter connect: ns_id=%llu, pid=%u sockfd=%d, addr_ptr=%p (failed to read addr), addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, addr_ptr, addrlen);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_CONNECT;
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
    __s32 event_id = SYS_ENTER_SHUTDOWN;

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
    __s32 event_id = SYS_EXIT_SHUTDOWN;
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
    __s32 event_id = SYS_ENTER_RECVFROM;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    __u32 len = BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);
    void *src_addr_ptr = (void *)BPF_CORE_READ(ctx, args[4]);
    __u64 *addrlen_ptr = (__u64 *)BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (src_addr_ptr == NULL || addrlen_ptr == NULL) {
                bpf_printk("Enter recvfrom: ns_id=%llu, pid=%u sockfd=%d, src address not requested\n", 
                    ct.ns_id, ct.pid, sockfd);
            } else {
                bpf_printk("Enter recvfrom: ns_id=%llu, pid=%u sockfd=%d, len=%u, flags=%d, src_addr_ptr=%p, addrlen_ptr=%p\n", 
                        ct.ns_id, ct.pid, sockfd, len, flags, src_addr_ptr, addrlen_ptr);
                return 0;
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_RECVFROM;
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
    __s32 event_id = SYS_ENTER_RECVMSG;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msg_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __s32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter recvmsg: ns_id=%llu, pid=%u sockfd=%d, msg_ptr=%p, flags=%d\n", 
                    ct.ns_id, ct.pid, sockfd, msg_ptr, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_RECVMSG;
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
    __s32 event_id = SYS_ENTER_RECVMMSG;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msgvec_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 vlen = BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);
    void *timeout_ptr = (void *)BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter recvmmsg: ns_id=%llu, pid=%u sockfd=%d, msgvec_ptr=%p, vlen=%u, flags=%d, timeout_ptr=%p\n", 
                    ct.ns_id, ct.pid, sockfd, msgvec_ptr, vlen, flags, timeout_ptr);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int trace_sys_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_RECVMMSG;
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
    __s32 event_id = SYS_ENTER_SENDTO;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *buf_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u64 len = BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);
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
                bpf_printk("Enter sendto: ns_id=%llu, pid=%u sockfd=%d, buf_ptr=%p, len=%llu, flags=%d, dest_addr=%u.%u.%u.%u:%u, addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, buf_ptr, len, flags, 
                        (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                        port, addrlen);
            } else {
                bpf_printk("Enter sendto: ns_id=%llu, pid=%u sockfd=%d, buf_ptr=%p, len=%llu, flags=%u, dest_addr_ptr=%p (failed to read dest_addr), addrlen=%u\n", 
                        ct.ns_id, ct.pid, sockfd, buf_ptr, len, flags, dest_addr_ptr, addrlen);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SENDTO;
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
    __s32 event_id = SYS_ENTER_SENDMSG;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msg_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __s32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched && *watched == LOGGING) {
        struct {
            void *msg_name;
            __u32 msg_namelen;
        } msg_info;

        if (bpf_probe_read_user(&msg_info, sizeof(msg_info), msg_ptr) == 0) {
            if (msg_info.msg_name && msg_info.msg_namelen >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in addr;
                if (bpf_probe_read_user(&addr, sizeof(addr), msg_info.msg_name) == 0) {
                    __u32 ip = addr.sin_addr.s_addr;
                    __u16 port = bpf_ntohs(addr.sin_port);
                    bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, dest_addr=%u.%u.%u.%u:%u, flags=%d\n", 
                            ct.ns_id, ct.pid, sockfd,
                            (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF),
                            port, flags);
                } else {
                    bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, msg_ptr=%p (failed to read dest_addr), flags=%d\n", 
                            ct.ns_id, ct.pid, sockfd, msg_ptr, flags);
                }
            } else {
                bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, msg_ptr=%p (no valid destination address), flags=%d\n", 
                        ct.ns_id, ct.pid, sockfd, msg_ptr, flags);
            }
        } else {
            bpf_printk("Enter sendmsg: ns_id=%llu, pid=%u sockfd=%d, msg_ptr=%p (failed to read msg_info), flags=%d\n", 
                    ct.ns_id, ct.pid, sockfd, msg_ptr, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SENDMSG;
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
    __s32 event_id = SYS_ENTER_SENDMMSG;

    __s32 sockfd = BPF_CORE_READ(ctx, args[0]);
    void *msgvec_ptr = (void *)BPF_CORE_READ(ctx, args[1]);
    __u32 vlen = BPF_CORE_READ(ctx, args[2]);
    __s32 flags = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter sendmmsg: ns_id=%llu, pid=%u sockfd=%d, msgvec_ptr=%p, vlen=%u, flags=%d\n", 
                    ct.ns_id, ct.pid, sockfd, msgvec_ptr, vlen, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int trace_sys_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SENDMMSG;
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
    __s32 event_id = SYS_ENTER_SETHOSTNAME;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    __u64 len = BPF_CORE_READ(ctx, args[1]);

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
                long err = bpf_probe_read_user_str(hostname, 256, name);
                if (err >= 0) {
                    bpf_printk("Enter sethostname: ns_id=%llu, pid=%u, hostname=%s, len=%llu\n", 
                            ct.ns_id, ct.pid, hostname, len);
                } else {
                    bpf_printk("Enter sethostname: ns_id=%llu, pid=%u, name_ptr=%p (failed to read hostname), len=%llu\n", 
                            ct.ns_id, ct.pid, name, len);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sethostname")
int trace_sys_exit_sethostname(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SETHOSTNAME;
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
    __s32 event_id = SYS_ENTER_SETDOMAINNAME;

    char *name = (char *)BPF_CORE_READ(ctx, args[0]);
    __u64 len = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 key = 0;
            char *domainname = bpf_map_lookup_elem(&buf_map, &key);
            if (domainname) {
                long err = bpf_probe_read_user_str(domainname, 256, name);
                if (err == 0) {
                    bpf_printk("Enter setdomainname: ns_id=%llu, pid=%u, domainname=%s, len=%llu\n", 
                            ct.ns_id, ct.pid, domainname, len);
                } else {
                    bpf_printk("Enter setdomainname: ns_id=%llu, pid=%u, name_ptr=%p (failed to read domainname), len=%llu\n", 
                            ct.ns_id, ct.pid, name, len);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setdomainname")
int trace_sys_exit_setdomainname(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SETDOMAINNAME;
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

SEC("tracepoint/syscalls/sys_enter_ioctl")
int trace_sys_enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_IOCTL;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u64 op = BPF_CORE_READ(ctx, args[1]);
    char *argp = (char *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter ioctl: ns_id=%llu, pid=%u, fd=%d, cmd=%llu, arg_ptr=%p\n", 
                    ct.ns_id, ct.pid, fd, op, argp);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int trace_sys_exit_ioctl(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_IOCTL;
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
                bpf_printk("Exit ioctl: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit ioctl: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int trace_sys_enter_poll(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_POLL;

    struct pollfd *fds = (struct pollfd *)BPF_CORE_READ(ctx, args[0]);
    __u64 nfds = BPF_CORE_READ(ctx, args[1]);
    __s32 timeout = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter poll: ns_id=%llu, pid=%u, fds_ptr=%p, nfds=%u, timeout=%d\n", 
                    ct.ns_id, ct.pid, fds, nfds, timeout);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_poll")
int trace_sys_exit_poll(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_POLL;
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
                bpf_printk("Exit poll: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit poll: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int trace_sys_enter_ppoll(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PPOLL;

    struct pollfd *fds = (struct pollfd *)BPF_CORE_READ(ctx, args[0]);
    __u64 nfds = BPF_CORE_READ(ctx, args[1]);
    void *tsp = (void *)BPF_CORE_READ(ctx, args[2]);
    void *sigmask = (void *)BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (sigmask == NULL && tsp == NULL) {
                bpf_printk("Enter ppoll: ns_id=%llu, pid=%u, fds_ptr=%p, nfds=%u, tsp_ptr=NULL (wait infinite), sigmask_ptr=NULL (using default sigmask)\n", 
                    ct.ns_id, ct.pid, fds, nfds);
            } else if (sigmask == NULL) {
                bpf_printk("Enter ppoll: ns_id=%llu, pid=%u, fds_ptr=%p, nfds=%u, tsp_ptr=%p, sigmask_ptr=NULL (using default sigmask)\n", 
                    ct.ns_id, ct.pid, fds, nfds, tsp);
            } else if (tsp == NULL) {
                bpf_printk("Enter ppoll: ns_id=%llu, pid=%u, fds_ptr=%p, nfds=%u, tsp_ptr=NULL (wait infinite), sigmask_ptr=%p\n", 
                    ct.ns_id, ct.pid, fds, nfds, sigmask);
            } else {
                bpf_printk("Enter ppoll: ns_id=%llu, pid=%u, fds_ptr=%p, nfds=%u, tsp_ptr=%p, sigmask_ptr=%p\n", 
                    ct.ns_id, ct.pid, fds, nfds, tsp, sigmask);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ppoll")
int trace_sys_exit_ppoll(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PPOLL;
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
                bpf_printk("Exit ppoll: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit ppoll: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create")
int trace_sys_enter_epoll_create(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_CREATE;

    __s32 size = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter epoll_create: ns_id=%llu, pid=%u, size=%d\n", 
                    ct.ns_id, ct.pid, size);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_create")
int trace_sys_exit_epoll_create(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_CREATE;
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
                bpf_printk("Exit epoll_create: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_create: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int trace_sys_enter_epoll_create1(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_CREATE1;

    __s32 flags = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter epoll_create1: ns_id=%llu, pid=%u, flags=%d\n", 
                    ct.ns_id, ct.pid, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_create1")
int trace_sys_exit_epoll_create1(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_CREATE1;
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
                bpf_printk("Exit epoll_create1: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_create1: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int trace_sys_enter_epoll_ctl(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_CTL;

    __s32 epfd = BPF_CORE_READ(ctx, args[0]);
    __s32 op = BPF_CORE_READ(ctx, args[1]);
    __s32 fd = BPF_CORE_READ(ctx, args[2]);
    struct epoll_event *event = (struct epoll_event *)BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (event == NULL) {
                bpf_printk("Enter epoll_ctl: ns_id=%llu, pid=%u, epfd=%d, op=%d, fd=%d, event_ptr=NULL\n", 
                        ct.ns_id, ct.pid, epfd, op, fd);
            } else {
                bpf_printk("Enter epoll_ctl: ns_id=%llu, pid=%u, epfd=%d, op=%d, fd=%d, event_ptr=%p\n", 
                        ct.ns_id, ct.pid, epfd, op, fd, event);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_ctl")
int trace_sys_exit_epoll_ctl(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_CTL;
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
                bpf_printk("Exit epoll_ctl: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_ctl: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int trace_sys_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_WAIT;

    __s32 epfd = BPF_CORE_READ(ctx, args[0]);
    struct epoll_event *events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1]);
    __s32 maxevents = BPF_CORE_READ(ctx, args[2]);
    __s32 timeout = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter epoll_wait: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout=%d\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, timeout);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int trace_sys_exit_epoll_wait(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_WAIT;
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
                bpf_printk("Exit epoll_wait: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_wait: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int trace_sys_enter_epoll_pwait(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_PWAIT;

    __s32 epfd = BPF_CORE_READ(ctx, args[0]);
    struct epoll_event *events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1]);
    __s32 maxevents = BPF_CORE_READ(ctx, args[2]);
    __s32 timeout = BPF_CORE_READ(ctx, args[3]);
    void *sigmask = (void *)BPF_CORE_READ(ctx, args[4]);
    __s32 sigsetsize = BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (sigmask == NULL) {
                bpf_printk("Enter epoll_pwait: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout=%d, sigmask_ptr=NULL (using default sigmask)\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, timeout);
            } else {
                bpf_printk("Enter epoll_pwait: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout=%d, sigmask_ptr=%p\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, timeout, sigmask);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int trace_sys_exit_epoll_pwait(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_PWAIT;
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
                bpf_printk("Exit epoll_pwait: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_pwait: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int trace_sys_enter_epoll_pwait2(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_EPOLL_PWAIT2;

    __s32 epfd = BPF_CORE_READ(ctx, args[0]);
    struct epoll_event *events = (struct epoll_event *)BPF_CORE_READ(ctx, args[1]);
    __s32 maxevents = BPF_CORE_READ(ctx, args[2]);
    void *timeout = (void *)BPF_CORE_READ(ctx, args[3]);
    void *sigmask = (void *)BPF_CORE_READ(ctx, args[4]);
    __s32 sigsetsize = BPF_CORE_READ(ctx, args[5]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (sigmask == NULL && timeout == NULL) {
                bpf_printk("Enter epoll_pwait2: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout_ptr=NULL (wait infinite), sigmask_ptr=NULL (using default sigmask)\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents);
            } else if (sigmask == NULL) {
                bpf_printk("Enter epoll_pwait2: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout_ptr=%p, sigmask_ptr=NULL (using default sigmask)\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, timeout);
            } else if (timeout == NULL) {
                bpf_printk("Enter epoll_pwait2: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout_ptr=NULL (wait infinite), sigmask_ptr=%p\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, sigmask);
            } else {
                bpf_printk("Enter epoll_pwait2: ns_id=%llu, pid=%u, epfd=%d, events_ptr=%p, maxevents=%d, timeout=%d, sigmask_ptr=%p\n", 
                    ct.ns_id, ct.pid, epfd, events, maxevents, timeout, sigmask);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait2")
int trace_sys_exit_epoll_pwait2(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_EPOLL_PWAIT2;
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
                bpf_printk("Exit epoll_pwait2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit epoll_pwait2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

// file system related tracepoints
SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_CLOSE;

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
    __s32 event_id = SYS_EXIT_CLOSE;
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
    __s32 event_id = SYS_ENTER_CREAT;

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
    __s32 event_id = SYS_EXIT_CREAT;
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
    __s32 event_id = SYS_ENTER_OPEN;

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
    __s32 event_id = SYS_EXIT_OPEN;
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
    __s32 event_id = SYS_ENTER_OPENAT;

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
    __s32 event_id = SYS_EXIT_OPENAT;
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
    __s32 event_id = SYS_ENTER_OPENAT2;

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
    __s32 event_id = SYS_EXIT_OPENAT2;
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
    __s32 event_id = SYS_ENTER_NAME_TO_HANDLE_AT;

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
    __s32 event_id = SYS_EXIT_NAME_TO_HANDLE_AT;
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
    __s32 event_id = SYS_ENTER_OPEN_BY_HANDLE_AT;

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
    __s32 event_id = SYS_EXIT_OPEN_BY_HANDLE_AT;
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
    __s32 event_id = SYS_ENTER_MEMFD_CREATE;

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
    __s32 event_id = SYS_EXIT_MEMFD_CREATE;
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

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_sys_enter_mknod(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_MKNOD;

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
    __s32 event_id = SYS_EXIT_MKNOD;
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
    __s32 event_id = SYS_ENTER_MKNODAT;

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
    __s32 event_id = SYS_EXIT_MKNODAT;
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
    __s32 event_id = SYS_ENTER_RENAME;

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
    __s32 event_id = SYS_EXIT_RENAME;
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
    __s32 event_id = SYS_ENTER_RENAMEAT;

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
    __s32 event_id = SYS_EXIT_RENAMEAT;
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
    __s32 event_id = SYS_ENTER_RENAMEAT2;

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
    __s32 event_id = SYS_EXIT_RENAMEAT2;
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
    __s32 event_id = SYS_ENTER_TRUNCATE;

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
    __s32 event_id = SYS_EXIT_TRUNCATE;
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
    __s32 event_id = SYS_ENTER_FTRUNCATE;

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
    __s32 event_id = SYS_EXIT_FTRUNCATE;
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
    __s32 event_id = SYS_ENTER_FALLOCATE;

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
    __s32 event_id = SYS_EXIT_FALLOCATE;
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
    __s32 event_id = SYS_ENTER_MKDIR;

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
    __s32 event_id = SYS_EXIT_MKDIR;
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
    __s32 event_id = SYS_ENTER_MKDIRAT;

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
    __s32 event_id = SYS_EXIT_MKDIRAT;
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
    __s32 event_id = SYS_ENTER_RMDIR;

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
    __s32 event_id = SYS_EXIT_RMDIR;
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
    __s32 event_id = SYS_ENTER_GETCWD;

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
    __s32 event_id = SYS_EXIT_GETCWD;
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
    __s32 event_id = SYS_ENTER_CHDIR;

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
    __s32 event_id = SYS_EXIT_CHDIR;
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
    __s32 event_id = SYS_ENTER_FCHDIR;

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
    __s32 event_id = SYS_EXIT_FCHDIR;
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
    __s32 event_id = SYS_ENTER_CHROOT;

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
    __s32 event_id = SYS_EXIT_CHROOT;
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
    __s32 event_id = SYS_ENTER_GETDENTS;

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
    __s32 event_id = SYS_EXIT_GETDENTS;
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
    __s32 event_id = SYS_ENTER_GETDENTS64;

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
    __s32 event_id = SYS_EXIT_GETDENTS64;
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
    __s32 event_id = SYS_ENTER_LINK;

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
    __s32 event_id = SYS_EXIT_LINK;
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
    __s32 event_id = SYS_ENTER_LINKAT;

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
    __s32 event_id = SYS_EXIT_LINKAT;
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

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_sys_enter_symlink(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_SYMLINK;

    char *target = (char *)BPF_CORE_READ(ctx, args[0]);
    char *linkpath = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 target_key = 0;
            __u32 link_key = 1;
            char *target_buf = bpf_map_lookup_elem(&buf_map, &target_key);
            char *link_buf = bpf_map_lookup_elem(&buf_map, &link_key);
            if (target_buf && link_buf) {
                long target_err = bpf_probe_read_user(target_buf, sizeof(char) * 256, target);
                long link_err = bpf_probe_read_user(link_buf, sizeof(char) * 256, linkpath);
                if (target_err == 0 && link_err == 0) {
                    bpf_printk("Enter symlink: ns_id=%llu, pid=%u, target=%s, linkpath=%s\n", 
                            ct.ns_id, ct.pid, target_buf, link_buf);
                } else {
                    bpf_printk("Enter symlink: ns_id=%llu, pid=%u, failed to read target\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_sys_exit_symlink(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SYMLINK;
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
                bpf_printk("Exit symlink: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit symlink: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_sys_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_SYMLINKAT;

    char *target = (char *)BPF_CORE_READ(ctx, args[0]);
    __s32 dirfd = BPF_CORE_READ(ctx, args[1]);
    char *linkpath = (char *)BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 target_key = 0;
            __u32 link_key = 1;
            char *target_buf = bpf_map_lookup_elem(&buf_map, &target_key);
            char *link_buf = bpf_map_lookup_elem(&buf_map, &link_key);
            if (target_buf && link_buf) {
                long target_err = bpf_probe_read_user(target_buf, sizeof(char) * 256, target);
                long link_err = bpf_probe_read_user(link_buf, sizeof(char) * 256, linkpath);
                if (target_err == 0 && link_err == 0) {
                    bpf_printk("Enter symlinkat: ns_id=%llu, pid=%u, dirfd=%d, target=%s, linkpath=%s\n", 
                            ct.ns_id, ct.pid, dirfd, target_buf, link_buf);
                } else {
                    bpf_printk("Enter symlinkat: ns_id=%llu, pid=%u, failed to read target\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlinkat")
int trace_sys_exit_symlinkat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SYMLINKAT;
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
                bpf_printk("Exit symlinkat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit symlinkat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UNLINK;

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
                    bpf_printk("Enter unlink: ns_id=%llu, pid=%u, pathname=%s\n", 
                            ct.ns_id, ct.pid, path);
                } else {
                    bpf_printk("Enter unlink: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_sys_exit_unlink(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UNLINK;
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
                bpf_printk("Exit unlink: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit unlink: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UNLINKAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);

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
                    bpf_printk("Enter unlinkat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, flags=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path, flags);
                } else {
                    bpf_printk("Enter unlinkat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UNLINKAT;
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
                bpf_printk("Exit unlinkat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit unlinkat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int trace_sys_enter_readlink(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_READLINK;

    char *path = (char *)BPF_CORE_READ(ctx, args[0]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 bufsize = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            if (path_buf ) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, path);
                if (path_err == 0) {
                    bpf_printk("Enter readlink: ns_id=%llu, pid=%u, path=%s, buf_addr=%p, bufsize=%u\n", 
                            ct.ns_id, ct.pid, path_buf, buf, bufsize);
                } else {
                    bpf_printk("Enter readlink: ns_id=%llu, pid=%u, failed to read path\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readlink")
int trace_sys_exit_readlink(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_READLINK;
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
                bpf_printk("Exit readlink: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit readlink: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int trace_sys_enter_readlinkat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_READLINKAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *path = (char *)BPF_CORE_READ(ctx, args[1]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 bufsize = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            if (path_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, path);
                if (path_err == 0) {
                    bpf_printk("Enter readlinkat: ns_id=%llu, pid=%u, dirfd=%d, path=%s, buf_addr=%p, bufsize=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, buf, bufsize);
                } else {
                    bpf_printk("Enter readlinkat: ns_id=%llu, pid=%u, failed to read path\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readlinkat")
int trace_sys_exit_readlinkat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_READLINKAT;
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
                bpf_printk("Exit readlinkat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit readlinkat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int trace_sys_enter_umask(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UMASK;

    __u32 mask = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter umask: ns_id=%llu, pid=%u, mask=%u\n", 
                    ct.ns_id, ct.pid, mask);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_umask")
int trace_sys_exit_umask(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UMASK;
    __u32 ret = BPF_CORE_READ(ctx, ret);
    
    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };
    
    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (ret < 0) {
                bpf_printk("Exit umask: failed, ns_id=%llu, pid=%u, error_code=%u\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit umask: success, ns_id=%llu, pid=%u, ret=%u\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int trace_sys_enter_stat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_NEWSTAT;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    struct stat64 *statbuf = (struct stat64 *)BPF_CORE_READ(ctx, args[1]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {
                    bpf_printk("Enter newstat: ns_id=%llu, pid=%u, filename=%s, statbuf_addr=%p\n", 
                            ct.ns_id, ct.pid, path_buf, statbuf);
                } else {
                    bpf_printk("Enter newstat: ns_id=%llu, pid=%u, failed to read filename\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newstat")
int trace_sys_exit_stat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_NEWSTAT;
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
                bpf_printk("Exit newstat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit newstat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int trace_sys_enter_lstat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_NEWLSTAT;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    struct stat64 *statbuf = (struct stat64 *)BPF_CORE_READ(ctx, args[1]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {
                    bpf_printk("Enter newlstat: ns_id=%llu, pid=%u, filename=%s, statbuf_addr=%p\n", 
                            ct.ns_id, ct.pid, path_buf, statbuf);
                } else {
                    bpf_printk("Enter newlstat: ns_id=%llu, pid=%u, failed to read filename\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newlstat")
int trace_sys_exit_lstat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_NEWLSTAT;
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
                bpf_printk("Exit newlstat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit newlstat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int trace_sys_enter_fstat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_NEWFSTAT;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct stat64 *statbuf = (struct stat64 *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fstat: ns_id=%llu, pid=%u, fd=%d, statbuf_addr=%p\n", 
                    ct.ns_id, ct.pid, fd, statbuf);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int trace_sys_exit_fstat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_NEWFSTAT;
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
                bpf_printk("Exit newfstat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit newfstat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int trace_sys_enter_fstatat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_NEWFSTATAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    struct stat64 *statbuf = (struct stat64 *)BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter newfstatat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, statbuf_addr=%p, flags=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, statbuf, flags);
                } else {
                    bpf_printk("Enter newfstatat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int trace_sys_exit_fstatat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_NEWFSTATAT;
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
                bpf_printk("Exit newfstatat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit newfstatat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int trace_sys_enter_statx(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_STATX;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);
    __u32 mask = BPF_CORE_READ(ctx, args[3]);
    struct statx *statxbuf = (struct statx *)BPF_CORE_READ(ctx, args[4]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter statx: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, flags=%u, mask=%u, statxbuf_addr=%p\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, flags, mask, statxbuf);
                } else {
                    bpf_printk("Enter statx: ns_id=%llu, pid=%u, failed to read pathname\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_statx")
int trace_sys_exit_statx(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_STATX;
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
                bpf_printk("Exit statx: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit statx: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int trace_sys_enter_statfs(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_STATFS;

    char *path = (char *)BPF_CORE_READ(ctx, args[0]);
    struct statfs *buf = (struct statfs *)BPF_CORE_READ(ctx, args[1]);

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
                    bpf_printk("Enter statfs: ns_id=%llu, pid=%u, path=%s, buf_addr=%p\n", 
                            ct.ns_id, ct.pid, path_buf, buf);
                } else {
                    bpf_printk("Enter statfs: ns_id=%llu, pid=%u, failed to read path\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_statfs")
int trace_sys_exit_statfs(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_STATFS;
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
                bpf_printk("Exit statfs: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit statfs: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int trace_sys_enter_fstatfs(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FSTATFS;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct statfs *buf = (struct statfs *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fstatfs: ns_id=%llu, pid=%u, fd=%d, buf_addr=%p\n", 
                    ct.ns_id, ct.pid, fd, buf);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fstatfs")
int trace_sys_exit_fstatfs(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FSTATFS;
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
                bpf_printk("Exit fstatfs: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fstatfs: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_sys_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_CHMOD;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
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
            char *path_buf = bpf_map_lookup_elem(&buf_map, &key);
            if (path_buf) {
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {
                    bpf_printk("Enter chmod: ns_id=%llu, pid=%u, filename=%s, mode=%u\n", 
                            ct.ns_id, ct.pid, path_buf, mode);
                } else {
                    bpf_printk("Enter chmod: ns_id=%llu, pid=%u, failed to read filename\n", 
                            ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int trace_sys_exit_chmod(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_CHMOD;
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
                bpf_printk("Exit chmod: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit chmod: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FCHMOD;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u32 mode = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fchmod: ns_id=%llu, pid=%u, fd=%d, mode=%u\n", 
                    ct.ns_id, ct.pid, fd, mode);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int trace_sys_exit_fchmod(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FCHMOD;
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
                bpf_printk("Exit fchmod: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fchmod: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FCHMODAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 mode = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter fchmodat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, mode=%u, flags=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, mode, flags);
                } else {
                    bpf_printk("Enter fchmodat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int trace_sys_exit_fchmodat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FCHMODAT;
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
                bpf_printk("Exit fchmodat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fchmodat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_sys_enter_chown(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_CHOWN;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 user = BPF_CORE_READ(ctx, args[1]);
    __u32 group = BPF_CORE_READ(ctx, args[2]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {         
                    bpf_printk("Enter chown: ns_id=%llu, pid=%u, filename=%s, user=%u, group=%u\n", 
                            ct.ns_id, ct.pid, path_buf, user, group);
                } else {
                    bpf_printk("Enter chown: ns_id=%llu, pid=%u, failed to read filename\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chown")
int trace_sys_exit_chown(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_CHOWN;
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
                bpf_printk("Exit chown: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit chown: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int trace_sys_enter_lchown(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LCHOWN;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    __u32 user = BPF_CORE_READ(ctx, args[1]);
    __u32 group = BPF_CORE_READ(ctx, args[2]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {
                    bpf_printk("Enter lchown: ns_id=%llu, pid=%u, filename=%s, user=%u, group=%u\n", 
                            ct.ns_id, ct.pid, path_buf, user, group);
                } else {
                    bpf_printk("Enter lchown: ns_id=%llu, pid=%u, failed to read filename\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lchown")
int trace_sys_exit_lchown(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LCHOWN;
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
                bpf_printk("Exit lchown: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit lchown: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_sys_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FCHOWN;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u32 user = BPF_CORE_READ(ctx, args[1]);
    __u32 group = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fchown: ns_id=%llu, pid=%u, fd=%d, user=%u, group=%u\n", 
                    ct.ns_id, ct.pid, fd, user, group);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int trace_sys_exit_fchown(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FCHOWN;
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
                bpf_printk("Exit fchown: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fchown: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_sys_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FCHOWNAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 user = BPF_CORE_READ(ctx, args[2]);
    __u32 group = BPF_CORE_READ(ctx, args[3]);
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
            char *path_buf = bpf_map_lookup_elem(&buf_map, &key);
            if (path_buf) {
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter fchownat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, user=%u, group=%u, flags=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, user, group, flags);
                } else {
                    bpf_printk("Enter fchownat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int trace_sys_exit_fchownat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FCHOWNAT;
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
                bpf_printk("Exit fchownat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fchownat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utime")
int trace_sys_enter_utime(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UTIME;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    struct utimbuf *times = (struct utimbuf *)BPF_CORE_READ(ctx, args[1]);

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
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (path_err == 0) {
                    if (times) {
                        struct utimbuf time_values;
                        long times_err = bpf_probe_read_user(&time_values, sizeof(struct utimbuf), times);
                        if (times_err == 0) {
                            bpf_printk("Enter utime: ns_id=%llu, pid=%u, filename=%s, actime=%lld, modtime=%lld\n", 
                                       ct.ns_id, ct.pid, path_buf, time_values.actime, time_values.modtime);
                        } else {
                            bpf_printk("Enter utime: ns_id=%llu, pid=%u, filename=%s, failed to read times\n", 
                                       ct.ns_id, ct.pid, path_buf);
                        }
                    } else {
                        bpf_printk("Enter utime: ns_id=%llu, pid=%u, filename=%s, times=NULL (using current time)\n", 
                                   ct.ns_id, ct.pid, path_buf);
                    }
                } else {
                    bpf_printk("Enter utime: ns_id=%llu, pid=%u, failed to read filename\n", 
                               ct.ns_id, ct.pid); 
                }
            }
        }
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_utime")
int trace_sys_exit_utime(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UTIME;
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
                bpf_printk("Exit utime: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit utime: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimes")
int trace_sys_enter_utimes(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UTIMES;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
    struct __kernel_old_timeval *utimes = (struct __kernel_old_timeval *)BPF_CORE_READ(ctx, args[1]);

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
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (path_err == 0) {
                    if (utimes) {
                        struct __kernel_old_timeval time_values[2];
                        long utimes_err = bpf_probe_read_user(&time_values, sizeof(time_values), utimes);
                        if (utimes_err == 0) {
                            bpf_printk("Enter utimes: ns_id=%llu, pid=%u, filename=%s, actime=%lld.%06ld, modtime=%lld.%06ld\n", 
                                       ct.ns_id, ct.pid, path_buf, 
                                       (long long)time_values[0].tv_sec, (long)time_values[0].tv_usec,
                                       (long long)time_values[1].tv_sec, (long)time_values[1].tv_usec);
                        } else {
                            bpf_printk("Enter utimes: ns_id=%llu, pid=%u, filename=%s, failed to read utimes\n", 
                                       ct.ns_id, ct.pid, path_buf);
                        }
                    } else {
                        bpf_printk("Enter utimes: ns_id=%llu, pid=%u, filename=%s, utimes=NULL (using current time)\n", 
                                   ct.ns_id, ct.pid, path_buf);
                    }
                } else {
                    bpf_printk("Enter utimes: ns_id=%llu, pid=%u, failed to read filename\n", 
                               ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_utimes")
int trace_sys_exit_utimes(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UTIMES;
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
                bpf_printk("Exit utimes: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit utimes: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futimesat")
int trace_sys_enter_futimesat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FUTIMESAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    struct __kernel_old_timeval *utimes = (struct __kernel_old_timeval *)BPF_CORE_READ(ctx, args[2]);

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
                if (pathname == NULL) {
                    bpf_printk("Enter futimesat: ns_id=%llu, pid=%u, dirfd=%d, pathname=NULL (using dirfd), utimes=%p\n", 
                                ct.ns_id, ct.pid, dirfd, utimes);
                } else {
                    long path_err = bpf_probe_read_user(path_buf, 256, pathname);
                    if (path_err == 0) {
                        if (utimes) {
                            struct __kernel_old_timeval time_values[2];
                            long utimes_err = bpf_probe_read_user(&time_values, sizeof(time_values), utimes);
                            if (utimes_err == 0) {
                                bpf_printk("Enter futimesat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, actime=%lld.%06ld, modtime=%lld.%06ld\n", 
                                        ct.ns_id, ct.pid, dirfd, path_buf, 
                                        (long long)time_values[0].tv_sec, (long)time_values[0].tv_usec,
                                        (long long)time_values[1].tv_sec, (long)time_values[1].tv_usec);
                            } else {
                                bpf_printk("Enter futimesat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, failed to read utimes, err=%ld\n", 
                                        ct.ns_id, ct.pid, dirfd, path_buf, utimes_err);
                            }
                        } else {
                            bpf_printk("Enter futimesat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, utimes=NULL (using current time)\n", 
                                    ct.ns_id, ct.pid, dirfd, path_buf);
                        }
                    } else {
                        bpf_printk("Enter futimesat: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname, err=%ld\n", 
                                ct.ns_id, ct.pid, dirfd, path_err);
                    }
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futimesat")
int trace_sys_exit_futimesat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FUTIMESAT;
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
                bpf_printk("Exit futimesat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit futimesat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int trace_sys_enter_utimensat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_UTIMENSAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    struct timespec64 *utimes = (struct timespec64 *)BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);

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
                if (pathname == NULL) {
                    bpf_printk("Enter utimensat: ns_id=%llu, pid=%u, dirfd=%d, pathname=NULL (using current directory(if dirfd is 0 or -100) or dirfd), flags=%u\n", 
                                ct.ns_id, ct.pid, dirfd, flags);
                } else {
                    long path_err = bpf_probe_read_user(path_buf, 256, pathname);
                    if (path_err == 0) {
                        if (utimes) {
                            struct timespec64 time_values[2];
                            long utimes_err = bpf_probe_read_user(&time_values, sizeof(time_values), utimes);
                            if (utimes_err == 0) {
                                bpf_printk("Enter utimensat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, actime=%lld.%09ld, modtime=%lld.%09ld, flags=%u\n", 
                                        ct.ns_id, ct.pid, dirfd, path_buf, 
                                        (long long)time_values[0].tv_sec, time_values[0].tv_nsec,
                                        (long long)time_values[1].tv_sec, time_values[1].tv_nsec, flags);
                            } else {
                                bpf_printk("Enter utimensat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, failed to read utimes, err=%ld\n", 
                                        ct.ns_id, ct.pid, dirfd, path_buf, utimes_err);
                            }
                        } else {
                            bpf_printk("Enter utimensat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, utimes=NULL (using current time), flags=%u\n", 
                                    ct.ns_id, ct.pid, dirfd, path_buf, flags);
                        }
                    } else {
                        bpf_printk("Enter utimensat: ns_id=%llu, pid=%u, dirfd=%d, failed to read pathname, err=%ld\n", 
                                ct.ns_id, ct.pid, dirfd, path_err);
                    }
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_utimensat")
int trace_sys_exit_utimensat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_UTIMENSAT;
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
                bpf_printk("Exit utimensat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit utimensat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int trace_sys_enter_access(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_ACCESS;

    char *filename = (char *)BPF_CORE_READ(ctx, args[0]);
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
            char *path_buf = bpf_map_lookup_elem(&buf_map, &key);
            if (path_buf) {
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, filename);
                if (err == 0) {
                    bpf_printk("Enter access: ns_id=%llu, pid=%u, filename=%s, mode=%u\n", 
                            ct.ns_id, ct.pid, path_buf, mode);
                } else {
                    bpf_printk("Enter access: ns_id=%llu, pid=%u, failed to read filename\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_access")
int trace_sys_exit_access(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_ACCESS;
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
                bpf_printk("Exit access: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit access: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int trace_sys_enter_faccessat(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FACCESSAT;

    __s32 dirfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 mode = BPF_CORE_READ(ctx, args[2]);
    __u32 flags = BPF_CORE_READ(ctx, args[3]);

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
                long err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                if (err == 0) {
                    bpf_printk("Enter faccessat: ns_id=%llu, pid=%u, dirfd=%d, pathname=%s, mode=%u, flags=%u\n", 
                            ct.ns_id, ct.pid, dirfd, path_buf, mode, flags);
                } else {
                    bpf_printk("Enter faccessat: ns_id=%llu, pid=%u, failed to read pathname\n", 
                    ct.ns_id, ct.pid);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_faccessat")
int trace_sys_exit_faccessat(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FACCESSAT;
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
                bpf_printk("Exit faccessat: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit faccessat: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_sys_enter_setxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_SETXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            __u32 value_key = 2;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            char *value_buf = bpf_map_lookup_elem(&buf_map, &value_key);
            if (path_buf && name_buf && value_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                __u32 read_size = (size > 256) ? 256 : size;
                long value_err = bpf_probe_read_user(value_buf, read_size, value);
                if (path_err == 0 && name_err == 0 && value_err == 0) {
                    if (size > 256) {
                        bpf_printk("Enter setxattr: ns_id=%llu, pid=%u, pathname=%s, name=%s, value=(truncated), size=%u (truncated to %u), flags=%u\n", 
                                ct.ns_id, ct.pid, path_buf, name_buf, size, read_size, flags);
                    } else {
                        bpf_printk("Enter setxattr: ns_id=%llu, pid=%u, pathname=%s, name=%s, value=%s, size=%u, flags=%u\n", 
                                ct.ns_id, ct.pid, path_buf, name_buf, value_buf, size, flags);
                    }
                } else {
                    bpf_printk("Enter setxattr: ns_id=%llu, pid=%u, failed to read pathname, name, or value. Errors: path=%ld, name=%ld, value=%ld\n", 
                            ct.ns_id, ct.pid, path_err, name_err, value_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int trace_sys_exit_setxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SETXATTR;
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
                bpf_printk("Exit setxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit setxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int trace_sys_enter_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LSETXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            __u32 value_key = 2;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            char *value_buf = bpf_map_lookup_elem(&buf_map, &value_key);
            if (path_buf && name_buf && value_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                __u32 read_size = (size > 256) ? 256 : size;
                long value_err = bpf_probe_read_user(value_buf, read_size, value);
                if (path_err == 0 && name_err == 0 && value_err == 0) {
                    if (size > 256) {
                        bpf_printk("Enter lsetxattr: ns_id=%llu, pid=%u, pathname=%s, name=%s, value=(truncated), size=%u (truncated to %u), flags=%u\n", 
                                ct.ns_id, ct.pid, path_buf, name_buf, size, read_size, flags);
                    } else {
                        bpf_printk("Enter lsetxattr: ns_id=%llu, pid=%u, pathname=%s, name=%s, value=%s, size=%u, flags=%u\n", 
                                ct.ns_id, ct.pid, path_buf, name_buf, value_buf, size, flags);
                    }
                } else {
                    bpf_printk("Enter lsetxattr: ns_id=%llu, pid=%u, failed to read pathname, name, or value. Errors: path=%ld, name=%ld, value=%ld\n", 
                            ct.ns_id, ct.pid, path_err, name_err, value_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lsetxattr")
int trace_sys_exit_lsetxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LSETXATTR;
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
                bpf_printk("Exit lsetxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit lsetxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int trace_sys_enter_fsetxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FSETXATTR;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 name_key = 0;
            __u32 value_key = 1;
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            char *value_buf = bpf_map_lookup_elem(&buf_map, &value_key);
            if (name_buf && value_buf) {
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                __u32 read_size = (size > 256) ? 256 : size;
                long value_err = bpf_probe_read_user(value_buf, read_size, value);
                if (name_err == 0 && value_err == 0) {
                    if (size > 256) {
                        bpf_printk("Enter fsetxattr: ns_id=%llu, pid=%u, fd=%d, name=%s, value=(truncated), size=%u (truncated to %u), flags=%u\n", 
                                ct.ns_id, ct.pid, fd, name_buf, size, read_size, flags);
                    } else {
                        bpf_printk("Enter fsetxattr: ns_id=%llu, pid=%u, fd=%d, name=%s, value=%s, size=%u, flags=%u\n", 
                                ct.ns_id, ct.pid, fd, name_buf, value_buf, size, flags);
                    }
                } else {
                    bpf_printk("Enter fsetxattr: ns_id=%llu, pid=%u, failed to read name or value. Errors: name=%ld, value=%ld\n", 
                            ct.ns_id, ct.pid, name_err, value_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsetxattr")
int trace_sys_exit_fsetxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FSETXATTR;
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
                bpf_printk("Exit fsetxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fsetxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_sys_enter_getxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_GETXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (path_buf && name_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (path_err == 0 && name_err == 0) {
                    if (size == 0) {
                        bpf_printk("Enter getxattr (size query): ns_id=%llu, pid=%u, pathname=%s, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, name_buf, value, size);
                    } else {
                        bpf_printk("Enter getxattr (value query): ns_id=%llu, pid=%u, pathname=%s, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, name_buf, value, size);
                    }
                } else {
                    bpf_printk("Enter getxattr: ns_id=%llu, pid=%u, failed to read pathname or name. Errors: path=%ld, name=%ld\n", 
                                ct.ns_id, ct.pid, path_err, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getxattr")
int trace_sys_exit_getxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_GETXATTR;
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
                bpf_printk("Exit getxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit getxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int trace_sys_enter_lgetxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LGETXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (path_buf && name_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (path_err == 0 && name_err == 0) {
                    if (size == 0) {
                        bpf_printk("Enter lgetxattr (size query): ns_id=%llu, pid=%u, pathname=%s, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, name_buf, value, size);
                    } else {
                        bpf_printk("Enter lgetxattr (value query): ns_id=%llu, pid=%u, pathname=%s, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, name_buf, value, size);
                    }
                } else {
                    bpf_printk("Enter lgetxattr: ns_id=%llu, pid=%u, failed to read pathname or name. Errors: path=%ld, name=%ld\n", 
                                ct.ns_id, ct.pid, path_err, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lgetxattr")
int trace_sys_exit_lgetxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LGETXATTR;
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
                bpf_printk("Exit lgetxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit lgetxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int trace_sys_enter_fgetxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FGETXATTR;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);
    char *value = (char *)BPF_CORE_READ(ctx, args[2]);
    __u32 size = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 name_key = 0;
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (name_buf) {
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (name_err == 0) {
                    if (size == 0) {
                        bpf_printk("Enter fgetxattr (size query): ns_id=%llu, pid=%u, fd=%d, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, fd, name_buf, value, size);
                    } else {
                        bpf_printk("Enter fgetxattr (value query): ns_id=%llu, pid=%u, fd=%d, name=%s, value_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, fd, name_buf, value, size);
                    }
                } else {
                    bpf_printk("Enter fgetxattr: ns_id=%llu, pid=%u, failed to read name. Errors: name=%ld\n", 
                                ct.ns_id, ct.pid, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fgetxattr")
int trace_sys_exit_fgetxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FGETXATTR;
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
                bpf_printk("Exit fgetxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fgetxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int trace_sys_enter_listxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LISTXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *list = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 size = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            if (path_buf) {
                long path_err = bpf_probe_read_user(path_buf, 256, pathname);
                if (path_err == 0) {
                    if (pathname == NULL) {
                        bpf_printk("Enter listxattr: ns_id=%llu, pid=%u, pathname=NULL (current directory), list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, list, size);
                    } else if (size == 0) {
                        bpf_printk("Enter listxattr (size query): ns_id=%llu, pid=%u, pathname=%s, list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, list, size);
                    } else {
                        bpf_printk("Enter listxattr (list query): ns_id=%llu, pid=%u, pathname=%s, list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, list, size);
                    }
                } else {
                    bpf_printk("Enter listxattr: ns_id=%llu, pid=%u, failed to read pathname, err=%ld\n", 
                                ct.ns_id, ct.pid, path_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listxattr")
int trace_sys_exit_listxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LISTXATTR;
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
                bpf_printk("Exit listxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit listxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int trace_sys_enter_llistxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LLISTXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *list = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 size = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            if (path_buf) {
                long path_err = bpf_probe_read_user(path_buf, 256, pathname);
                if (path_err == 0) {
                    if (pathname == NULL) {
                        bpf_printk("Enter llistxattr: ns_id=%llu, pid=%u, pathname=NULL (current directory), list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, list, size);
                    } else if (size == 0) {
                        bpf_printk("Enter llistxattr (size query): ns_id=%llu, pid=%u, pathname=%s, list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, list, size);
                    } else {
                        bpf_printk("Enter llistxattr (list query): ns_id=%llu, pid=%u, pathname=%s, list_addr=%p, size=%u\n", 
                                    ct.ns_id, ct.pid, path_buf, list, size);
                    }
                } else {
                    bpf_printk("Enter llistxattr: ns_id=%llu, pid=%u, failed to read pathname, err=%ld\n", 
                                ct.ns_id, ct.pid, path_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_llistxattr")
int trace_sys_exit_llistxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LLISTXATTR;
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
                bpf_printk("Exit llistxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit llistxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int trace_sys_enter_flistxattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FLISTXATTR;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *list = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 size = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            if (size == 0) {
                bpf_printk("Enter flistxattr (size query): ns_id=%llu, pid=%u, fd=%d, list_addr=%p, size=%u\n", 
                            ct.ns_id, ct.pid, fd, list, size);
            } else {
                bpf_printk("Enter flistxattr (list query): ns_id=%llu, pid=%u, fd=%d, list_addr=%p, size=%u\n", 
                            ct.ns_id, ct.pid, fd, list, size);
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flistxattr")
int trace_sys_exit_flistxattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FLISTXATTR;
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
                bpf_printk("Exit flistxattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit flistxattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int trace_sys_enter_removexattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_REMOVEXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (path_buf && name_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (path_err == 0 && name_err == 0) {
                    bpf_printk("Enter removexattr: ns_id=%llu, pid=%u, pathname=%s, name=%s\n", 
                            ct.ns_id, ct.pid, path_buf, name_buf);
                } else {
                    bpf_printk("Enter removexattr: ns_id=%llu, pid=%u, failed to read pathname or name. Errors: path=%ld, name=%ld\n", 
                            ct.ns_id, ct.pid, path_err, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_removexattr")
int trace_sys_exit_removexattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_REMOVEXATTR;
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
                bpf_printk("Exit removexattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit removexattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int trace_sys_enter_lremovexattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LREMOVEXATTR;

    char *pathname = (char *)BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 path_key = 0;
            __u32 name_key = 1;
            char *path_buf = bpf_map_lookup_elem(&buf_map, &path_key);
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (path_buf && name_buf) {
                long path_err = bpf_probe_read_user(path_buf, sizeof(char) * 256, pathname);
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (path_err == 0 && name_err == 0) {
                    bpf_printk("Enter lremovexattr: ns_id=%llu, pid=%u, pathname=%s, name=%s\n", 
                            ct.ns_id, ct.pid, path_buf, name_buf);
                } else {
                    bpf_printk("Enter lremovexattr: ns_id=%llu, pid=%u, failed to read pathname or name. Errors: path=%ld, name=%ld\n", 
                            ct.ns_id, ct.pid, path_err, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lremovexattr")
int trace_sys_exit_lremovexattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LREMOVEXATTR;
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
                bpf_printk("Exit lremovexattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit lremovexattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int trace_sys_enter_fremovexattr(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FREMOVEXATTR;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *name = (char *)BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 name_key = 0;
            char *name_buf = bpf_map_lookup_elem(&buf_map, &name_key);
            if (name_buf) {
                long name_err = bpf_probe_read_user(name_buf, sizeof(char) * 256, name);
                if (name_err == 0) {
                    bpf_printk("Enter fremovexattr: ns_id=%llu, pid=%u, fd=%d, name=%s\n", 
                            ct.ns_id, ct.pid, fd, name_buf);
                } else {
                    bpf_printk("Enter fremovexattr: ns_id=%llu, pid=%u, failed to read name. Errors: name=%ld\n", 
                            ct.ns_id, ct.pid, name_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fremovexattr")
int trace_sys_exit_fremovexattr(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FREMOVEXATTR;
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
                bpf_printk("Exit fremovexattr: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fremovexattr: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_sys_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FCNTL;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u64 cmd = BPF_CORE_READ(ctx, args[1]);
    __u64 arg = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fcntl: ns_id=%llu, pid=%u, fd=%d, cmd=%llu, arg_addr=%p\n", 
                    ct.ns_id, ct.pid, fd, cmd, arg);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_sys_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FCNTL;
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
                bpf_printk("Exit fcntl: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fcntl: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_sys_enter_dup(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_DUP;

    __s32 oldfd = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter dup: ns_id=%llu, pid=%u, oldfd=%d\n", 
                    ct.ns_id, ct.pid, oldfd);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int trace_sys_exit_dup(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_DUP;
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
                bpf_printk("Exit dup: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit dup: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_DUP2;

    __s32 oldfd = BPF_CORE_READ(ctx, args[0]);
    __s32 newfd = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter dup2: ns_id=%llu, pid=%u, oldfd=%d, newfd=%d\n", 
                    ct.ns_id, ct.pid, oldfd, newfd);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_DUP2;
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
                bpf_printk("Exit dup2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit dup2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_DUP3;

    __s32 oldfd = BPF_CORE_READ(ctx, args[0]);
    __s32 newfd = BPF_CORE_READ(ctx, args[1]);
    __u32 flags = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter dup3: ns_id=%llu, pid=%u, oldfd=%d, newfd=%d, flags=%u\n", 
                    ct.ns_id, ct.pid, oldfd, newfd, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int trace_sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_DUP3;
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
                bpf_printk("Exit dup3: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit dup3: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int trace_sys_enter_flock(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FLOCK;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u32 op = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter flock: ns_id=%llu, pid=%u, fd=%d, op=%u\n", 
                    ct.ns_id, ct.pid, fd, op);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_flock")
int trace_sys_exit_flock(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FLOCK;
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
                bpf_printk("Exit flock: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit flock: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_READ;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 count = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter read: ns_id=%llu, pid=%u, fd=%d, buf_addr=%p, count=%u\n", 
                    ct.ns_id, ct.pid, fd, buf, count);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_READ;
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
                bpf_printk("Exit read: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit read: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_sys_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PREAD64;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[1]);
    __u64 count = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter pread64: ns_id=%llu, pid=%u, fd=%d, buf_addr=%p, count=%llu, offset=%llu\n", 
                    ct.ns_id, ct.pid, fd, buf, count, offset);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int trace_sys_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PREAD64;
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
                bpf_printk("Exit pread64: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit pread64: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int trace_sys_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_READV;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter readv: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int trace_sys_exit_readv(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_READV;
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
                bpf_printk("Exit readv: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit readv: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int trace_sys_enter_preadv(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PREADV;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter preadv: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u, offset=%llu\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt, offset);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv")
int trace_sys_exit_preadv(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PREADV;
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
                bpf_printk("Exit preadv: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit preadv: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int trace_sys_enter_preadv2(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PREADV2;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter preadv2: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u, offset=%llu, flags=%u\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt, offset, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv2")
int trace_sys_exit_preadv2(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PREADV2;
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
                bpf_printk("Exit preadv2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit preadv2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_WRITE;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[1]);
    __u64 count = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 buf_key = 0;
            char *buf_buf = bpf_map_lookup_elem(&buf_map, &buf_key);
            if (buf_buf) {
                __u64 read_count = (count > 255) ? 255 : count;
                long buf_err = bpf_probe_read_user(buf_buf, read_count, buf);
                if (buf_err == 0) {
                    buf_buf[read_count] = '\0';
                    if (count > 255) {
                        bpf_printk("Enter write: ns_id=%llu, pid=%u, fd=%d, buf=(truncated), count=%llu (truncated to %u)\n", 
                            ct.ns_id, ct.pid, fd, count, read_count);
                    } else {
                        bpf_printk("Enter write: ns_id=%llu, pid=%u, fd=%d, buf=%s, count=%llu\n", 
                            ct.ns_id, ct.pid, fd, buf_buf, count);
                    } 
                } else {
                    bpf_printk("Enter write: ns_id=%llu, pid=%u, failed to read buf. Errors: buf=%ld\n", 
                            ct.ns_id, ct.pid, buf_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_WRITE;
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
                bpf_printk("Exit write: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit write: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PWRITE64;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *buf = (char *)BPF_CORE_READ(ctx, args[1]);
    __u64 count = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 buf_key = 0;
            char *buf_buf = bpf_map_lookup_elem(&buf_map, &buf_key);
            if (buf_buf) {
                __u64 read_count = (count > 255) ? 255 : count;
                long buf_err = bpf_probe_read_user(buf_buf, read_count, buf);
                if (buf_err == 0) {
                    buf_buf[read_count] = '\0';
                    if (count > 255) {
                        bpf_printk("Enter pwrite64: ns_id=%llu, pid=%u, fd=%d, buf=(truncated), count=%llu (truncated to %u), offset=%llu\n", 
                            ct.ns_id, ct.pid, fd, count, read_count, offset);
                    } else {
                        bpf_printk("Enter pwrite64: ns_id=%llu, pid=%u, fd=%d, buf=%s, count=%llu, offset=%llu\n", 
                            ct.ns_id, ct.pid, fd, buf_buf, count, offset);
                    }
                } else {
                    bpf_printk("Enter pwrite64: ns_id=%llu, pid=%u, failed to read buf. Errors: buf=%ld\n", 
                            ct.ns_id, ct.pid, buf_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PWRITE64;
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
                bpf_printk("Exit pwrite64: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit pwrite64: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_WRITEV;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter writev: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_WRITEV;
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
                bpf_printk("Exit writev: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit writev: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int trace_sys_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PWRITEV;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter pwritev: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u, offset=%llu\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt, offset);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev")
int trace_sys_exit_pwritev(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PWRITEV;
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
                bpf_printk("Exit pwritev: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit pwritev: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int trace_sys_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_PWRITEV2;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(ctx, args[1]);
    __u32 iovcnt = BPF_CORE_READ(ctx, args[2]);
    __u64 offset = BPF_CORE_READ(ctx, args[3]);
    __u32 flags = BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter pwritev2: ns_id=%llu, pid=%u, fd=%d, iov_addr=%p, iovcnt=%u, offset=%llu, flags=%u\n", 
                    ct.ns_id, ct.pid, fd, iov, iovcnt, offset, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev2")
int trace_sys_exit_pwritev2(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_PWRITEV2;
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
                bpf_printk("Exit pwritev2: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit pwritev2: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int trace_sys_enter_lseek(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_LSEEK;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __u64 offset = BPF_CORE_READ(ctx, args[1]);
    __u32 whence = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter lseek: ns_id=%llu, pid=%u, fd=%d, offset=%llu, whence=%u\n", 
                    ct.ns_id, ct.pid, fd, offset, whence);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int trace_sys_exit_lseek(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_LSEEK;
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
                bpf_printk("Exit lseek: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit lseek: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int trace_sys_enter_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_SENDFILE64;

    __s32 out_fd = BPF_CORE_READ(ctx, args[0]);
    __s32 in_fd = BPF_CORE_READ(ctx, args[1]);
    __u64 offset = BPF_CORE_READ(ctx, args[2]);
    __u64 count = BPF_CORE_READ(ctx, args[3]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter sendfile64: ns_id=%llu, pid=%u, out_fd=%d, in_fd=%d, offset=%llu, count=%llu\n", 
                    ct.ns_id, ct.pid, out_fd, in_fd, offset, count);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile64")
int trace_sys_exit_sendfile64(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_SENDFILE64;
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
                bpf_printk("Exit sendfile64: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit sendfile64: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init")
int trace_sys_enter_inotify_init(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_INOTIFY_INIT;

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter inotify_init: ns_id=%llu, pid=%u\n", 
                    ct.ns_id, ct.pid);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_init")
int trace_sys_exit_inotify_init(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_INOTIFY_INIT;
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
                bpf_printk("Exit inotify_init: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit inotify_init: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int trace_sys_enter_inotify_init1(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_INOTIFY_INIT1;

    __u32 flags = BPF_CORE_READ(ctx, args[0]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter inotify_init1: ns_id=%llu, pid=%u, flags=%u\n", 
                    ct.ns_id, ct.pid, flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_init1")
int trace_sys_exit_inotify_init1(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_INOTIFY_INIT1;
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
                bpf_printk("Exit inotify_init1: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit inotify_init1: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int trace_sys_enter_inotify_add_watch(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_INOTIFY_ADD_WATCH;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[1]);
    __u32 mask = BPF_CORE_READ(ctx, args[2]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 buf_key = 0;
            char *buf_buf = bpf_map_lookup_elem(&buf_map, &buf_key);
            if (buf_buf) {
                long buf_err = bpf_probe_read_user(buf_buf, sizeof(char) * 256, pathname);
                if (buf_err == 0) {
                    bpf_printk("Enter inotify_add_watch: ns_id=%llu, pid=%u, fd=%d, pathname=%s, mask=%u\n", 
                        ct.ns_id, ct.pid, fd, buf_buf, mask);
                } else {
                    bpf_printk("Enter inotify_add_watch: ns_id=%llu, pid=%u, failed to read pathname. Errors: pathname=%ld\n", 
                        ct.ns_id, ct.pid, buf_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_add_watch")
int trace_sys_exit_inotify_add_watch(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_INOTIFY_ADD_WATCH;
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
                bpf_printk("Exit inotify_add_watch: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit inotify_add_watch: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int trace_sys_enter_inotify_rm_watch(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_INOTIFY_RM_WATCH;

    __s32 fd = BPF_CORE_READ(ctx, args[0]);
    __s32 wd = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
        bpf_printk("Enter inotify_rm_watch: ns_id=%llu, pid=%u, fd=%d, wd=%d\n", 
            ct.ns_id, ct.pid, fd, wd);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_inotify_rm_watch")
int trace_sys_exit_inotify_rm_watch(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_INOTIFY_RM_WATCH;
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
                bpf_printk("Exit inotify_rm_watch: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit inotify_rm_watch: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int trace_sys_enter_fanotify_init(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FANOTIFY_INIT;

    __u32 flags = BPF_CORE_READ(ctx, args[0]);
    __u32 event_f_flags = BPF_CORE_READ(ctx, args[1]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            bpf_printk("Enter fanotify_init: ns_id=%llu, pid=%u, flags=%u, event_f_flags=%u\n", 
                ct.ns_id, ct.pid, flags, event_f_flags);
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fanotify_init")
int trace_sys_exit_fanotify_init(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FANOTIFY_INIT;
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
                bpf_printk("Exit fanotify_init: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fanotify_init: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int trace_sys_enter_fanotify_mark(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_FANOTIFY_MARK;

    __s32 fanotify_fd = BPF_CORE_READ(ctx, args[0]);
    __u32 flags = BPF_CORE_READ(ctx, args[1]);
    __u64 mask = BPF_CORE_READ(ctx, args[2]);
    __s32 fd = BPF_CORE_READ(ctx, args[3]);
    char *pathname = (char *)BPF_CORE_READ(ctx, args[4]);

    struct current_task ct = get_task_struct();

    struct event_key event_key = {
        .ns_id = ct.ns_id,
        .event_id = event_id,
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &event_key);
    if (watched) {
        if (*watched == LOGGING) {
            __u32 buf_key = 0;
            char *buf_buf = bpf_map_lookup_elem(&buf_map, &buf_key);
            if (buf_buf) {
                if (pathname == NULL) {
                    bpf_printk("Enter fanotify_mark: ns_id=%llu, pid=%u, fanotify_fd=%d, flags=%u, mask=%llu, fd=%d, pathname=NULL\n", 
                        ct.ns_id, ct.pid, fanotify_fd, flags, mask, fd);
                    return 0;
                }
                long buf_err = bpf_probe_read_user(buf_buf, sizeof(char) * 256, pathname);
                if (buf_err == 0) {
                    bpf_printk("Enter fanotify_mark: ns_id=%llu, pid=%u, fanotify_fd=%d, flags=%u, mask=%llu, fd=%d, pathname=%s\n", 
                        ct.ns_id, ct.pid, fanotify_fd, flags, mask, fd, buf_buf);
                } else {
                    bpf_printk("Enter fanotify_mark: ns_id=%llu, pid=%u, failed to read pathname. Errors: pathname=%ld\n", 
                        ct.ns_id, ct.pid, buf_err);
                }
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fanotify_mark")
int trace_sys_exit_fanotify_mark(struct trace_event_raw_sys_exit *ctx) {
    __s32 event_id = SYS_EXIT_FANOTIFY_MARK;
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
                bpf_printk("Exit fanotify_mark: failed, ns_id=%llu, pid=%u, error_code=%ld\n", ct.ns_id, ct.pid, ret);
            } else {
                bpf_printk("Exit fanotify_mark: success, ns_id=%llu, pid=%u ret=%ld\n", ct.ns_id, ct.pid, ret);
            }
        }
    }
    
    return 0;
}










SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    __s32 event_id = SYS_ENTER_MMAP;

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
    __s32 event_id = SYS_EXIT_MMAP;
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
    __s32 event_id = SYS_ENTER_MUNMAP;

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
    __s32 event_id = SYS_EXIT_MUNMAP;
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
    __s32 event_id = SYS_ENTER_MPROTECT;

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
    __s32 event_id = SYS_EXIT_MPROTECT;
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
    __s32 event_id = SYS_ENTER_PKEY_MPROTECT;

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
    __s32 event_id = SYS_EXIT_PKEY_MPROTECT;
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