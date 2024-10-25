#include "handler.h"

#define NANOSECONDS_IN_A_SECOND 1000000000
#define MAX_EVENT_ID 1024

time_t boot_time;

static void get_task_info_str(const struct current_task *task, char *buffer, size_t buffer_size, time_t boot_time) {
    char timestamp[26];
    time_t timer, actual_time;

    timer = task->timestamp / NANOSECONDS_IN_A_SECOND;
    unsigned long long nanoseconds = task->timestamp % NANOSECONDS_IN_A_SECOND;
    actual_time = boot_time + timer;
    struct tm *tm_info = gmtime(&actual_time);
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    snprintf(buffer, buffer_size,
             "count=%20llu, timestamp=%s.%9llu, cgroup_id=%20llu, ns_id=%9u, "
             "ppid=%9u, pid=%9u, tid=%9u, uid=%9u, gid=%9u",
             task->count, timestamp, nanoseconds,
             task->cgroup_id, task->ns_id,
             task->ppid, task->pid, task->tid,
             task->uid, task->gid);
}

typedef int (*event_handler_t)(const struct event_t*, const char*);

static void get_ip_str(const struct event_t *e, char *ip_str, size_t str_len) {
    memset(ip_str, 0, str_len);
    
    if (e->addr_family == AF_INET) {
        inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
    } else if (e->addr_family == AF_INET6) {
        inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
    }
}

struct socket_handlers {
    event_handler_t enter;
    event_handler_t exit;
};

static int handle_enter_socket(const struct event_t *e, const char *task_info) {
    printf("Enter socket: %s, domain=%d, type=%d, protocol=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_socket(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit socket: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit socket: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_socketpair(const struct event_t *e, const char *task_info) {
    printf("Enter socketpair: %s, domain=%d, type=%d, protocol=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_socketpair(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit socketpair: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit socketpair: success, %s, sv[0]=%d, sv[1]=%d, ret=%lld\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->ret);
    } else {
        printf("Exit socketpair: success but failed to read socket values, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_setsockopt(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter setsockopt: %s, socktfd=%d, level=%d, optname=%d, optval=%u, optlen=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_u32[0], e->arg_s32[3]);
    } else {
        printf("Enter setsockopt: %s, socktfd=%d, level=%d, optname=%d, failed to read optval, optlen=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_s32[3]);
    }
    return 0;
}

static int handle_exit_setsockopt(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit setsockopt: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit setsockopt: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getsockopt(const struct event_t *e, const char *task_info) {
    printf("Enter getsockopt: %s, socketfd=%d, level=%d, optname=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_getsockopt(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getsockopt: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit getsockopt: success, %s, optval=%u, optlen=%u, ret=%lld\n",
                task_info, e->arg_u32[0], e->arg_u32[1], e->ret);
    } else {
        printf("Exit getsockopt: success, %s, failed to read optval, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getsockname(const struct event_t *e, const char *task_info) {
    printf("Enter getsockname: %s, socketfd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_getsockname(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getsockname: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit getsockname: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit getsockname: success, %s, failed to read socket address info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getpeername(const struct event_t *e, const char *task_info) {
    printf("Enter getpeername: %s, socketfd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_getpeername(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getpeername: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit getpeername: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit getpeername: success, %s, failed to read socket address info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_bind(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Enter bind: %s, socktfd=%d, addr=%s:%u, ip_version=%s\n",
                task_info, e->arg_s32[0], ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
    } else {
        printf("Enter bind: %s, socktfd=%d, failed to read address info\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_bind(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit bind: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit bind: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_listen(const struct event_t *e, const char *task_info) {
    printf("Enter listen: %s, socktfd=%d, backlog=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_listen(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit listen: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit listen: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_accept(const struct event_t *e, const char *task_info) {
    printf("Enter accept: %s, socktfd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_accept(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit accept: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_null == true) {
        printf("Exit accept: success, %s, socket address info is not requested, ret=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit accept: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit accept: success, %s, failed to read socket address info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_accept4(const struct event_t *e, const char *task_info) {
    printf("Enter accept4: %s, socktfd=%d, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_accept4(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit accept4: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_null == true) {
        printf("Exit accept4: success, %s, socket address info is not requested, ret=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit accept4: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit accept4: success, %s, failed to read socket address info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_connect(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Enter connect: %s, socktfd=%d, addr=%s:%u, ip_version=%s\n",
                task_info, e->arg_s32[0], ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
    } else {
        printf("Enter connect: %s, socktfd=%d, failed to read address info\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_connect(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit connect: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit connect: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_shutdown(const struct event_t *e, const char *task_info) {
    printf("Enter shutdown: %s, socketfd=%d, how=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_shutdown(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit shutdown: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit shutdown: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_recvfrom (const struct event_t *e, const char *task_info) {
    printf("Enter recvfrom: %s, socktfd=%d, msg_len=%llu, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_recvfrom(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit recvfrom: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_null == true) {
        printf("Exit recvfrom: success, %s, socket address info is not requested, ret=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit recvfrom: success, %s, src_addr=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit recvfrom: success, %s, failed to read source info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_recvmsg(const struct event_t *e, const char *task_info) {
    printf("Enter recvmsg: %s, socktfd=%d, msg_len=%llu, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_recvmsg(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit recvmsg: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Exit recvmsg: success, %s, src_addr=%s:%u, ip_version=%s, ret=%lld\n",
                task_info, ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
    } else {
        printf("Exit recvmsg: success, %s, failed to read source info, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_recvmmsg(const struct event_t *e, const char *task_info) {
    printf("Enter recvmmsg: %s, socktfd=%d, vlen=%u, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_recvmmsg(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit recvmmsg: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit recvmmsg: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_sendto(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Enter sendto: %s, socktfd=%d, msg_len=%llu, flags=%d, dest_addr=%s:%u, ip_version=%s\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1], ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
    } else {
        printf("Enter sendto: %s, socktfd=%d, msg_len=%llu, flags=%d, failed to read destination info\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_sendto(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit sendto: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit sendto: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_sendmsg(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        printf("Enter sendmsg: %s, socktfd=%d, flags=%d, dest_addr=%s:%u, ip_version=%s\n",
                task_info, e->arg_s32[0], e->arg_s32[1], ip_str, e->port, 
                e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
    } else {
        printf("Enter sendmsg: %s, socktfd=%d, flags=%d, failed to read destination info\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_sendmsg(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit sendmsg: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit sendmsg: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_sendmmsg(const struct event_t *e, const char *task_info) {
    printf("Enter sendmmsg: %s, socktfd=%d, vlen=%u, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_sendmmsg(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit sendmmsg: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit sendmmsg: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_sethostname(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter sethostname: %s, hostname=%s, len=%llu\n",
                task_info, e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter sethostname: %s, failed to read hostname, len=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_sethostname(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit sethostname: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit sethostname: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_setdomainname(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter setdomainname: %s, domainname=%s, len=%llu\n",
                task_info, e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter setdomainname: %s, failed to read domainname, len=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_setdomainname(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit setdomainname: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit setdomainname: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_ioctl(const struct event_t *e, const char *task_info) {
    printf("Enter ioctl: %s, fd=%d, op=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_ioctl(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit ioctl: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit ioctl: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_poll(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter poll: %s, nfds=%llu, timeout=%d, pollfd=%d, event=%d\n",
                task_info, e->arg_u64[0], e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    } else {
        printf("Enter poll: %s, nfds=%llu, timeout=%d, failed to read pollfd array\n",
                task_info, e->arg_u64[0], e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_poll(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit poll: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit poll: success, %s, revents=%d, ret=%llu\n",
                task_info, e->arg_s32[0], e->ret);
    } else {
        printf("Exit poll: success, %s, failed to read revents, ret=%llu\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_ppoll(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->arg_u64[1] == 999999999) {
            printf("Enter ppoll: %s, nfds=%llu, timeout=infinite, pollfd=%d, event=%d\n",
                    task_info, e->arg_u64[0], e->arg_s32[1], e->arg_s32[2]);
        } else {
            printf("Enter ppoll: %s, nfds=%llu, timeout=%llu.%09llu, pollfd=%d, event=%d\n",
                    task_info, e->arg_u64[0], e->arg_u64[1], e->arg_u64[2],
                    e->arg_s32[1], e->arg_s32[2]);
        }
    } else {
        printf("Enter ppoll: %s, nfds=%llu, failed to read pollfd array\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_ppoll(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit ppoll: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit ppoll: success, %s, revents=%d, ret=%lld\n",
                task_info, e->arg_s32[0], e->ret);
    } else {
        printf("Exit ppoll: success, %s, failed to read revents, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_create(const struct event_t *e, const char *task_info) {
    printf("Enter epoll_create: %s, size=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_epoll_create(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_create: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit epoll_create: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_create1(const struct event_t *e, const char *task_info) {
    printf("Enter epoll_create1: %s, flags=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_epoll_create1(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_create1: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit epoll_create1: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_ctl(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter epoll_ctl: %s, epfd=%d, op=%d, fd=%d, event=%u, data=%llu\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_u32[0], e->arg_u64[0]);
    } else {
        printf("Enter epoll_ctl: %s, epfd=%d, op=%d, failed to read event\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_epoll_ctl(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_ctl: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit epoll_ctl: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_wait(const struct event_t *e, const char *task_info) {
    printf("Enter epoll_wait: %s, epfd=%d, maxevents=%d, timeout=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_epoll_wait(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_wait: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit epoll_wait: success, %s, events=%d, data=%llu, ret=%lld\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
    } else {
        printf("Exit epoll_wait: success, %s, failed to read revents, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_pwait(const struct event_t *e, const char *task_info) {
    printf("Enter epoll_pwait: %s, epfd=%d, maxevents=%d, timeout=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_epoll_pwait(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_pwait: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit epoll_pwait: success, %s, events=%d, data=%llu, ret=%lld\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
    } else {
        printf("Exit epoll_pwait: success, %s, failed to read revents, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_epoll_pwait2(const struct event_t *e, const char *task_info) {
    if (e->arg_u64[0] == 999999999) {
        printf("Enter epoll_pwait2: %s, epfd=%d, maxevents=%d, timeout=infinite\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    } else {
        printf("Enter epoll_pwait2: %s, epfd=%d, maxevents=%d, timeout=%llu.%09llu\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u64[0], e->arg_u64[1]);
    }
    return 0;
}

static int handle_exit_epoll_pwait2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit epoll_pwait2: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit epoll_pwait2: success, %s, events=%d, data=%llu, ret=%lld\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
    } else {
        printf("Exit epoll_pwait2: success, %s, failed to read revents, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}


static struct socket_handlers event_handler[MAX_EVENT_ID] = {0};

void init_event_handlers(void) {
    event_handler[__NR_socket].enter = handle_enter_socket;
    event_handler[__NR_socket].exit = handle_exit_socket;
    event_handler[__NR_socketpair].enter = handle_enter_socketpair;
    event_handler[__NR_socketpair].exit = handle_exit_socketpair;
    event_handler[__NR_setsockopt].enter = handle_enter_setsockopt;
    event_handler[__NR_setsockopt].exit = handle_exit_setsockopt;
    event_handler[__NR_getsockopt].enter = handle_enter_getsockopt;
    event_handler[__NR_getsockopt].exit = handle_exit_getsockopt;
    event_handler[__NR_getsockname].enter = handle_enter_getsockname;
    event_handler[__NR_getsockname].exit = handle_exit_getsockname;
    event_handler[__NR_getpeername].enter = handle_enter_getpeername;
    event_handler[__NR_getpeername].exit = handle_exit_getpeername;
    event_handler[__NR_bind].enter = handle_enter_bind;
    event_handler[__NR_bind].exit = handle_exit_bind;
    event_handler[__NR_listen].enter = handle_enter_listen;
    event_handler[__NR_listen].exit = handle_exit_listen;
    event_handler[__NR_accept].enter = handle_enter_accept;
    event_handler[__NR_accept].exit = handle_exit_accept;
    event_handler[__NR_accept4].enter = handle_enter_accept4;
    event_handler[__NR_accept4].exit = handle_exit_accept4;
    event_handler[__NR_connect].enter = handle_enter_connect;
    event_handler[__NR_connect].exit = handle_exit_connect;
    event_handler[__NR_shutdown].enter = handle_enter_shutdown;
    event_handler[__NR_shutdown].exit = handle_exit_shutdown;
    event_handler[__NR_recvfrom].enter = handle_enter_recvfrom;
    event_handler[__NR_recvfrom].exit = handle_exit_recvfrom;
    event_handler[__NR_recvmsg].enter = handle_enter_recvmsg;
    event_handler[__NR_recvmsg].exit = handle_exit_recvmsg;
    event_handler[__NR_recvmmsg].enter = handle_enter_recvmmsg;
    event_handler[__NR_recvmmsg].exit = handle_exit_recvmmsg;
    event_handler[__NR_sendto].enter = handle_enter_sendto;
    event_handler[__NR_sendto].exit = handle_exit_sendto;
    event_handler[__NR_sendmsg].enter = handle_enter_sendmsg;
    event_handler[__NR_sendmsg].exit = handle_exit_sendmsg;
    event_handler[__NR_sendmmsg].enter = handle_enter_sendmmsg;
    event_handler[__NR_sendmmsg].exit = handle_exit_sendmmsg;
    event_handler[__NR_sethostname].enter = handle_enter_sethostname;
    event_handler[__NR_sethostname].exit = handle_exit_sethostname;
    event_handler[__NR_setdomainname].enter = handle_enter_setdomainname;
    event_handler[__NR_setdomainname].exit = handle_exit_setdomainname;
    event_handler[__NR_ioctl].enter = handle_enter_ioctl;
    event_handler[__NR_ioctl].exit = handle_exit_ioctl;
    event_handler[__NR_poll].enter = handle_enter_poll;
    event_handler[__NR_poll].exit = handle_exit_poll;
    event_handler[__NR_ppoll].enter = handle_enter_ppoll;
    event_handler[__NR_ppoll].exit = handle_exit_ppoll;
    event_handler[__NR_epoll_create].enter = handle_enter_epoll_create;
    event_handler[__NR_epoll_create].exit = handle_exit_epoll_create;
    event_handler[__NR_epoll_create1].enter = handle_enter_epoll_create1;
    event_handler[__NR_epoll_create1].exit = handle_exit_epoll_create1;
    event_handler[__NR_epoll_ctl].enter = handle_enter_epoll_ctl;
    event_handler[__NR_epoll_ctl].exit = handle_exit_epoll_ctl;
    event_handler[__NR_epoll_wait].enter = handle_enter_epoll_wait;
    event_handler[__NR_epoll_wait].exit = handle_exit_epoll_wait;
    event_handler[__NR_epoll_pwait].enter = handle_enter_epoll_pwait;
    event_handler[__NR_epoll_pwait].exit = handle_exit_epoll_pwait;
    event_handler[__NR_epoll_pwait2].enter = handle_enter_epoll_pwait2;
    event_handler[__NR_epoll_pwait2].exit = handle_exit_epoll_pwait2;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    char task_info[256];

    get_task_info_str(&e->task, task_info, sizeof(task_info), boot_time);
    
    struct socket_handlers *handlers = &event_handler[e->event_id];
    event_handler_t handler = e->is_enter ? handlers->enter : handlers->exit;
    if (handler) {
        return handler(e, task_info);
    }
    
    printf("Unknown event: %s, event_id=%lld\n", task_info, e->event_id);
    return 0;
}