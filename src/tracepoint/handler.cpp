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

static int handle_enter_close(const struct event_t *e, const char *task_info) {
    printf("Enter close: %s, fd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_close(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit close: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit close: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_creat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter creat: %s, pathname=%s, mode=%o\n",
                task_info, e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter creat: %s, failed to read pathname, mode=%o\n",
                task_info, e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_creat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit creat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit creat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_open(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter open: %s, pathname=%s, flags=%d, mode=%o\n",
                task_info, e->arg_str, e->arg_s32[0], e->arg_u32[0]);
    } else {
        printf("Enter open: %s, failed to read pathname, mode=%o\n",
                task_info, e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_open(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit open: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit open: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_openat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter openat: %s, dirfd=%d, pathname=%s, flags=%d, mode=%o\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_u32[0]);
    } else {
        printf("Enter openat: %s, dirfd=%d, failed to read pathname, flags=%d, mode=%o\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_openat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit openat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit openat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_openat2(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter openat2: %s, dirfd=%d, pathname=%s, flags=%llu, mode=%llo, resolve=%llu, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u64[1], e->arg_u64[2], e->arg_u64[3], e->arg_u64[0]);
    } else {
        printf("Enter openat2: %s, dirfd=%d, failed to read pathname, how, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_openat2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit openat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit openat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_name_to_handle_at(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter name_to_handle_at: %s, dirfd=%d, pathname=%s, handle_bytes=%u, handle_type=%d, mount_id=%d, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_s32[3], e->arg_s32[2], e->arg_s32[1]);
    } else {
        printf("Enter name_to_handle_at: %s, dirfd=%d, failed to read pathname, handle, mount_id, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_name_to_handle_at(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit name_to_handle_at: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit name_to_handle_at: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_open_by_handle_at(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter open_by_handle_at: %s, mount_fd=%d, handle_bytes=%u, handle_type=%d, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[2], e->arg_s32[1]);
    } else {
        printf("Enter open_by_handle_at: %s, mount_fd=%d, failed to read handle, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_open_by_handle_at(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit open_by_handle_at: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit open_by_handle_at: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_memfd_create(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter memfd_create: %s, name=%s, flags=%u\n",
                task_info, e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter memfd_create: %s, failed to read name, flags=%u\n",
                task_info, e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_memfd_create(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit memfd_create: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit memfd_create: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_mknod(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter mknod: %s, pathname=%s, mode=%o, dev=%llu\n",
                task_info, e->arg_str, e->arg_u32[0], e->arg_u64[0]);
    } else {
        printf("Enter mknod: %s, failed to read pathname, mode=%o, dev=%llu\n",
                task_info, e->arg_u32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_mknod(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit mknod: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit mknod: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_mknodat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter mknodat: %s, dirfd=%d, pathname=%s, mode=%o, dev=%llu\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_u64[0]);
    } else {
        printf("Enter mknodat: %s, dirfd=%d, failed to read pathname, mode=%o, dev=%llu\n",
                task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_mknodat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit mknodat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit mknodat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_rename(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter rename: %s, oldpath=%s, newpath=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter rename: %s, failed to read oldpath, newpath\n",
                task_info);
    }
    return 0;
}

static int handle_exit_rename(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit rename: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit rename: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_renameat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter renameat: %s, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2);
    } else {
        printf("Enter renameat: %s, olddirfd=%d, newdirfd=%d, failed to read oldpath, newpath\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_renameat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit renameat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit renameat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_renameat2(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter renameat2: %s, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2, e->arg_s32[2]);
    } else {
        printf("Enter renameat2: %s, olddirfd=%d, newdirfd=%d, failed to read oldpath, newpath, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    }
    return 0;
}

static int handle_exit_renameat2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit renameat2: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit renameat2: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_truncate(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter truncate: %s, path=%s, length=%llu\n",
                task_info, e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter truncate: %s, failed to read path, length=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_truncate(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit truncate: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit truncate: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_ftruncate(const struct event_t *e, const char *task_info) {
    printf("Enter ftruncate: %s, fd=%d, length=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_ftruncate(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit ftruncate: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit ftruncate: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fallocate(const struct event_t *e, const char *task_info) {
    printf("Enter fallocate: %s, fd=%d, mode=%d, offset=%llu, len=%llu\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u64[0], e->arg_u64[1]);
    return 0;
}

static int handle_exit_fallocate(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fallocate: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fallocate: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_mkdir(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter mkdir: %s, pathname=%s, mode=%o\n",
                task_info, e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter mkdir: %s, failed to read pathname, mode=%o\n",
                task_info, e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_mkdir(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit mkdir: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit mkdir: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_mkdirat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter mkdirat: %s, dirfd=%d, pathname=%s, mode=%o\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter mkdirat: %s, dirfd=%d, failed to read pathname, mode=%o\n",
                task_info, e->arg_s32[0], e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_mkdirat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit mkdirat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit mkdirat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_rmdir(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter rmdir: %s, pathname=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter rmdir: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_rmdir(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit rmdir: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit rmdir: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getcwd(const struct event_t *e, const char *task_info) {
    printf("Enter getcwd: %s, size=%llu\n",
            task_info, e->arg_u64[0]);
    return 0;
}

static int handle_exit_getcwd(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getcwd: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit getcwd: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_chdir(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter chdir: %s, pathname=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter chdir: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_chdir(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit chdir: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit chdir: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fchdir(const struct event_t *e, const char *task_info) {
    printf("Enter fchdir: %s, fd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_fchdir(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fchdir: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fchdir: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_chroot(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter chroot: %s, pathname=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter chroot: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_chroot(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit chroot: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit chroot: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_pivot_root(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter pivot_root: %s, new_root=%s, put_old=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter pivot_root: %s, failed to read new_root, put_old\n",
                task_info);
    }
    return 0;
}

static int handle_exit_pivot_root(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit pivot_root: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit pivot_root: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getdents(const struct event_t *e, const char *task_info) {
    printf("Enter getdents: %s, fd=%u, count=%u\n",
            task_info, e->arg_u32[0], e->arg_u32[1]);
    return 0;
}

static int handle_exit_getdents(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getdents: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit getdents: success, %s, data=%llu, ret=%lld, \n",
                task_info, e->arg_u64[0], e->ret);
    } else {
        printf("Exit getdents: success, %s, failed to read data, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getdents64(const struct event_t *e, const char *task_info) {
    printf("Enter getdents64: %s, fd=%d, count=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_getdents64(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getdents64: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else if (e->is_valid == true) {
        printf("Exit getdents64: success, %s, data=%llu, ret=%lld, \n",
                task_info, e->arg_u64[0], e->ret);
    } else {
        printf("Exit getdents64: success, %s, failed to read data, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_link(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter link: %s, oldpath=%s, newpath=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter link: %s, failed to read oldpath, newpath\n",
                task_info);
    }
    return 0;
}

static int handle_exit_link(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit link: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit link: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_linkat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter linkat: %s, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2, e->arg_s32[2]);
    } else {
        printf("Enter linkat: %s, olddirfd=%d, newdirfd=%d, failed to read oldpath, newpath, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    }
    return 0;
}

static int handle_exit_linkat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit linkat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit linkat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_symlink(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter symlink: %s, target=%s, linkpath=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter symlink: %s, failed to read target, linkpath\n",
                task_info);
    }
    return 0;
}

static int handle_exit_symlink(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit symlink: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit symlink: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_symlinkat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter symlinkat: %s, target=%s, newdirfd=%d, linkpath=%s\n",
                task_info, e->arg_str, e->arg_s32[0], e->arg_str2);
    } else {
        printf("Enter symlinkat: %s, newdirfd=%d, failed to read target, linkpath\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_symlinkat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit symlinkat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit symlinkat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_unlink(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter unlink: %s, pathname=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter unlink: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_unlink(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit unlink: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit unlink: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_unlinkat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter unlinkat: %s, dirfd=%d, pathname=%s, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1]);
    } else {
        printf("Enter unlinkat: %s, dirfd=%d, failed to read pathname, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_unlinkat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit unlinkat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit unlinkat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_readlink(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter readlink: %s, pathname=%s, size=%llu\n",
                task_info, e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter readlink: %s, failed to read pathname, size=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_readlink(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit readlink: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit readlink: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_readlinkat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter readlinkat: %s, dirfd=%d, pathname=%s, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter readlinkat: %s, dirfd=%d, failed to read pathname, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_readlinkat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit readlinkat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit readlinkat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_umask(const struct event_t *e, const char *task_info) {
    printf("Enter umask: %s, mask=%o\n",
            task_info, e->arg_u32[0]);
    return 0;
}

static int handle_exit_umask(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit umask: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit umask: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_newstat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter newstat: %s, filename=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter newstat: %s, failed to read filename\n",
                task_info);
    }
    return 0;
}

static int handle_exit_newstat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit newstat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit newstat: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_newlstat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter newlstat: %s, filename=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter newlstat: %s, failed to read filename\n",
                task_info);
    }
    return 0;
}

static int handle_exit_newlstat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit newlstat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit newlstat: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_newfstat(const struct event_t *e, const char *task_info) {
    printf("Enter newfstat: %s, fd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_newfstat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit newfstat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit newfstat: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_newfstatat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter newfstatat: %s, dirfd=%d, pathname=%s, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1]);
    } else {
        printf("Enter newfstatat: %s, dirfd=%d, failed to read pathname, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_newfstatat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit newfstatat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit newfstatat: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_statx(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter statx: %s, dirfd=%d, pathname=%s, flags=%d, mask=%o\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_u32[0]);
    } else {
        printf("Enter statx: %s, dirfd=%d, failed to read pathname, flags=%d, mask=%o\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_statx(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit statx: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit statx: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_statfs(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter statfs: %s, pathname=%s\n",
                task_info, e->arg_str);
    } else {
        printf("Enter statfs: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_statfs(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit statfs: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit statfs: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fstatfs(const struct event_t *e, const char *task_info) {
    printf("Enter fstatfs: %s, fd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_fstatfs(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fstatfs: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fstatfs: success, %s, ret=%lld, \n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_chmod(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter chmod: %s, pathname=%s, mode=%o\n",
                task_info, e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter chmod: %s, failed to read pathname, mode=%o\n",
                task_info, e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_chmod(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit chmod: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit chmod: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fchmod(const struct event_t *e, const char *task_info) {
    printf("Enter fchmod: %s, fd=%d, mode=%o\n",
            task_info, e->arg_s32[0], e->arg_u32[0]);
    return 0;
}

static int handle_exit_fchmod(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fchmod: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fchmod: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fchmodat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter fchmodat: %s, dirfd=%d, pathname=%s, mode=%o, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_s32[1]);
    } else {
        printf("Enter fchmodat: %s, dirfd=%d, failed to read pathname, mode=%o, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_fchmodat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fchmodat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fchmodat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_chown(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter chown: %s, pathname=%s, owner=%u, group=%u\n",
                task_info, e->arg_str, e->arg_u32[0], e->arg_u32[1]);
    } else {
        printf("Enter chown: %s, failed to read pathname, owner=%u, group=%u\n",
                task_info, e->arg_u32[0], e->arg_u32[1]);
    }
    return 0;
}

static int handle_exit_chown(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit chown: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit chown: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_lchown(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter lchown: %s, pathname=%s, owner=%u, group=%u\n",
                task_info, e->arg_str, e->arg_u32[0], e->arg_u32[1]);
    } else {
        printf("Enter lchown: %s, failed to read pathname, owner=%u, group=%u\n",
                task_info, e->arg_u32[0], e->arg_u32[1]);
    }
    return 0;
}

static int handle_exit_lchown(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit lchown: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit lchown: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fchown(const struct event_t *e, const char *task_info) {
    printf("Enter fchown: %s, fd=%d, owner=%u, group=%u\n",
            task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u32[1]);
    return 0;
}

static int handle_exit_fchown(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fchown: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fchown: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fchownat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter fchownat: %s, dirfd=%d, pathname=%s, owner=%u, group=%u, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_u32[1], e->arg_s32[1]);
    } else {
        printf("Enter fchownat: %s, dirfd=%d, failed to read pathname, owner=%u, group=%u, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u32[1], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_fchownat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fchownat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fchownat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_utime(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter utime: %s, pathname=%s, actime=%lld modetime=%lld\n",
                    task_info, e->arg_str, e->arg_u64[0], e->arg_u64[1]);
        } else {
            printf("Enter utime: %s, pathname=%s, time=current time\n",
                    task_info, e->arg_str);
        }
    } else {
        printf("Enter utime: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_utime(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit utime: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit utime: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_utimes(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter utimes: %s, pathname=%s, actime=%u.%d modetime=%u.%d\n",
                    task_info, e->arg_str, e->arg_u32[0], e->arg_s32[0], e->arg_u32[1], e->arg_s32[1]);
        } else {
            printf("Enter utimes: %s, pathname=%s, time=current time\n",
                    task_info, e->arg_str);
        }
    } else {
        printf("Enter utimes: %s, failed to read pathname\n",
                task_info);
    }
    return 0;
}

static int handle_exit_utimes(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit utimes: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit utimes: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_futimesat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter futimesat: %s, dirfd=%d, pathname=%s, actime=%u.%d modetime=%u.%d\n",
                    task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_s32[0], e->arg_u32[1], e->arg_s32[1]);
        } else {
            printf("Enter futimesat: %s, dirfd=%d, pathname=%s, time=current time\n",
                    task_info, e->arg_s32[0], e->arg_str);
        }
    } else {
        printf("Enter futimesat: %s, dirfd=%d, failed to read pathname\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_futimesat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit futimesat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit futimesat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_utimensat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter utimensat: %s, dirfd=%d, pathname=%s, actime=%llu.%llu modetime=%llu.%llu, flags=%d\n",
                    task_info, e->arg_s32[0], e->arg_str, e->arg_u64[0], e->arg_u64[1], e->arg_u64[2], e->arg_u64[3], e->arg_s32[1]);
        } else {
            printf("Enter utimensat: %s, dirfd=%d, pathname=%s, time=current time, flags=%d\n",
                    task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1]);
        }
    } else {
        printf("Enter utimensat: %s, dirfd=%d, failed to read pathname, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_utimensat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit utimensat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit utimensat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_access(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter access: %s, pathname=%s, mode=%o\n",
                task_info, e->arg_str, e->arg_s32[0]);
    } else {
        printf("Enter access: %s, failed to read pathname, mode=%o\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_access(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit access: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit access: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_faccessat(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter faccessat: %s, dirfd=%d, pathname=%s, mode=%o, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_s32[2]);
    } else {
        printf("Enter faccessat: %s, dirfd=%d, failed to read pathname, mode=%o, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    }
    return 0;
}

static int handle_exit_faccessat(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit faccessat: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit faccessat: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_setxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter setxattr: %s, pathname=%s, name=%s, size=%llu, flags=%d\n",
                task_info, e->arg_str, e->arg_str2, e->arg_u64[0], e->arg_s32[0]);
    } else {
        printf("Enter setxattr: %s, failed to read pathname, name, size=%llu, flags=%d\n",
                task_info, e->arg_u64[0], e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_setxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit setxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit setxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_lsetxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter lsetxattr: %s, pathname=%s, name=%s, size=%llu, flags=%d\n",
                task_info, e->arg_str, e->arg_str2, e->arg_u64[0], e->arg_s32[0]);
    } else {
        printf("Enter lsetxattr: %s, failed to read pathname, name, size=%llu, flags=%d\n",
                task_info, e->arg_u64[0], e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_lsetxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit lsetxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit lsetxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fsetxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter fsetxattr: %s, fd=%d, name=%s, size=%llu, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u64[0], e->arg_s32[0]);
    } else {
        printf("Enter fsetxattr: %s, fd=%d, failed to read name, size=%llu, flags=%d\n",
                task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_fsetxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fsetxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fsetxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_getxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter getxattr: %s, pathname=%s, name=%s, size=%llu\n",
                task_info, e->arg_str, e->arg_str2, e->arg_u64[0]);
    } else {
        printf("Enter getxattr: %s, failed to read pathname, name, size=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_getxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit getxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit getxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_lgetxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter lgetxattr: %s, pathname=%s, name=%s, size=%llu\n",
                task_info, e->arg_str, e->arg_str2, e->arg_u64[0]);
    } else {
        printf("Enter lgetxattr: %s, failed to read pathname, name, size=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_lgetxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit lgetxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit lgetxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fgetxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter fgetxattr: %s, fd=%d, name=%s, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u64[0]);
    } else {
        printf("Enter fgetxattr: %s, fd=%d, failed to read name, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_fgetxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fgetxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fgetxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_listxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter listxattr: %s, pathname=%s, list=%s, size=%llu\n",
                    task_info, e->arg_str, e->arg_str2, e->arg_u64[0]);
        } else {
            printf("Enter listxattr: %s, pathname=%s, buffer size needed, size=%llu\n",
                    task_info, e->arg_str, e->arg_u64[0]);
        }
    } else {
        printf("Enter listxattr: %s, failed to read pathname, size=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_listxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit listxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit listxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_llistxattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        if (e->is_null == false) {
            printf("Enter llistxattr: %s, pathname=%s, list=%s, size=%llu\n",
                    task_info, e->arg_str, e->arg_str2, e->arg_u64[0]);
        } else {
            printf("Enter llistxattr: %s, pathname=%s, buffer size needed, size=%llu\n",
                    task_info, e->arg_str, e->arg_u64[0]);
        }
    } else {
        printf("Enter llistxattr: %s, failed to read pathname, size=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_llistxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit llistxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit llistxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_flistxattr(const struct event_t *e, const char *task_info) {
    if (e->is_null == false) {
        if (e->is_valid) {
            printf("Enter flistxattr: %s, fd=%d, list=%s, size=%llu\n",
                    task_info, e->arg_s32[0], e->arg_str, e->arg_u64[0]);
        } else {
            printf("Enter flistxattr: %s, fd=%d, failed to read list, size=%llu\n",
                    task_info, e->arg_s32[0], e->arg_u64[0]);
        }
    } else {
        printf("Enter flistxattr: %s, fd=%d, buffer size needed, size=%llu\n",
                task_info, e->arg_s32[0], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_flistxattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit flistxattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit flistxattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_removexattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter removexattr: %s, pathname=%s, name=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter removexattr: %s, failed to read pathname, name\n",
                task_info);
    }
    return 0;
}

static int handle_exit_removexattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit removexattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit removexattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_lremovexattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter lremovexattr: %s, pathname=%s, name=%s\n",
                task_info, e->arg_str, e->arg_str2);
    } else {
        printf("Enter lremovexattr: %s, failed to read pathname, name\n",
                task_info);
    }
    return 0;
}

static int handle_exit_lremovexattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit lremovexattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit lremovexattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fremovexattr(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter fremovexattr: %s, fd=%d, name=%s\n",
                task_info, e->arg_s32[0], e->arg_str);
    } else {
        printf("Enter fremovexattr: %s, fd=%d, failed to read name\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_fremovexattr(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fremovexattr: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fremovexattr: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fcntl(const struct event_t *e, const char *task_info) {
    printf("Enter fcntl: %s, fd=%d, cmd=%llu, arg=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0], e->arg_u64[1]);
    return 0;
}

static int handle_exit_fcntl(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fcntl: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fcntl: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_dup(const struct event_t *e, const char *task_info) {
    printf("Enter dup: %s, oldfd=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_dup(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit dup: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit dup: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_dup2(const struct event_t *e, const char *task_info) {
    printf("Enter dup2: %s, oldfd=%d, newfd=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_dup2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit dup2: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit dup2: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_dup3(const struct event_t *e, const char *task_info) {
    printf("Enter dup3: %s, oldfd=%d, newfd=%d, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
    return 0;
}

static int handle_exit_dup3(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit dup3: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit dup3: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_flock(const struct event_t *e, const char *task_info) {
    printf("Enter flock: %s, fd=%d, operation=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_flock(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit flock: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit flock: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_read(const struct event_t *e, const char *task_info) {
    printf("Enter read: %s, fd=%d, count=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_read(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit read: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit read: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_pread64(const struct event_t *e, const char *task_info) {
    printf("Enter pread: %s, fd=%d, count=%llu, offset=%lld\n",
            task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s64[0]);
    return 0;
}

static int handle_exit_pread64(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit pread: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit pread: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_readv(const struct event_t *e, const char *task_info) {
    printf("Enter readv: %s, fd=%d, iov_count=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_readv(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit readv: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit readv: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_preadv(const struct event_t *e, const char *task_info) {
    printf("Enter preadv: %s, fd=%d, iov_count=%d, offset=%lld\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s64[0]);
    return 0;
}

static int handle_exit_preadv(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit preadv: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit preadv: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_preadv2(const struct event_t *e, const char *task_info) {
    printf("Enter preadv2: %s, fd=%d, iov_count=%d, offset=%lld, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_s32[2]);
    return 0;
}

static int handle_exit_preadv2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit preadv2: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit preadv2: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_write(const struct event_t *e, const char *task_info) {
    printf("Enter write: %s, fd=%d, count=%llu\n",
            task_info, e->arg_s32[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_write(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit write: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit write: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_pwrite64(const struct event_t *e, const char *task_info) {
    printf("Enter pwrite: %s, fd=%d, count=%llu, offset=%lld\n",
            task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s64[0]);
    return 0;
}

static int handle_exit_pwrite64(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit pwrite: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit pwrite: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_writev(const struct event_t *e, const char *task_info) {
    printf("Enter writev: %s, fd=%d, iov_count=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_writev(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit writev: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit writev: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_pwritev(const struct event_t *e, const char *task_info) {
    printf("Enter pwritev: %s, fd=%d, iov_count=%d, offset=%lld\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s64[0]);
    return 0;
}

static int handle_exit_pwritev(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit pwritev: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit pwritev: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_pwritev2(const struct event_t *e, const char *task_info) {
    printf("Enter pwritev2: %s, fd=%d, iov_count=%d, offset=%lld, flags=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_s32[2]);
    return 0;
}

static int handle_exit_pwritev2(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit pwritev2: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit pwritev2: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_lseek(const struct event_t *e, const char *task_info) {
    printf("Enter lseek: %s, fd=%d, offset=%lld, whence=%d\n",
            task_info, e->arg_s32[0], e->arg_s64[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_lseek(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit lseek: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit lseek: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_sendfile64(const struct event_t *e, const char *task_info) {
    printf("Enter sendfile64: %s, out_fd=%d, in_fd=%d, offset=%lld, count=%llu\n",
            task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_u64[0]);
    return 0;
}

static int handle_exit_sendfile64(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit sendfile64: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit sendfile64: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_inotify_init(const struct event_t *e, const char *task_info) {
    printf("Enter inotify_init: %s\n", task_info);
    return 0;
}

static int handle_exit_inotify_init(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit inotify_init: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit inotify_init: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_inotify_init1(const struct event_t *e, const char *task_info) {
    printf("Enter inotify_init1: %s, flags=%d\n",
            task_info, e->arg_s32[0]);
    return 0;
}

static int handle_exit_inotify_init1(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit inotify_init1: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit inotify_init1: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_inotify_add_watch(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter inotify_add_watch: %s, fd=%d, pathname=%s, mask=%o\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_u32[0]);
    } else {
        printf("Enter inotify_add_watch: %s, fd=%d, failed to read pathname, mask=%o\n",
                task_info, e->arg_s32[0], e->arg_u32[0]);
    }
    return 0;
}

static int handle_exit_inotify_add_watch(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit inotify_add_watch: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit inotify_add_watch: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_inotify_rm_watch(const struct event_t *e, const char *task_info) {
    printf("Enter inotify_rm_watch: %s, fd=%d, wd=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_inotify_rm_watch(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit inotify_rm_watch: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit inotify_rm_watch: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fanotify_init(const struct event_t *e, const char *task_info) {
    printf("Enter fanotify_init: %s, flags=%d, event_f_flags=%d\n",
            task_info, e->arg_s32[0], e->arg_s32[1]);
    return 0;
}

static int handle_exit_fanotify_init(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fanotify_init: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fanotify_init: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_fanotify_mark(const struct event_t *e, const char *task_info) {
    if (e->is_null == false) {
        if (e->is_valid == true) {
            printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%u, mask=%llo, dirfd=%d, pathname=%s\n",
                    task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1], e->arg_str);
        } else {
            printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%u, mask=%llo, dirfd=%d, failed to read pathname\n",
                    task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1]);
        }
    } else {
        printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%u, mask=%llo, dirfd=%d, pathname is NULL (monitoring directory events)\n",
                task_info, e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1]);
    }
    return 0;
}

static int handle_exit_fanotify_mark(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit fanotify_mark: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit fanotify_mark: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_mount(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter mount: %s, source=%s, target=%s, filesystemtype=%s, mountflags=%llu\n",
                task_info, e->arg_str, e->arg_str2, e->arg_str3, e->arg_u64[0]);
    } else {
        printf("Enter mount: %s, failed to read source, target, filesystemtype, mountflags=%llu\n",
                task_info, e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_mount(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit mount: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit mount: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_umount(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter umount: %s, target=%s, flags=%d\n",
                task_info, e->arg_str, e->arg_s32[0]);
    } else {
        printf("Enter umount: %s, failed to read target, flags=%d\n",
                task_info, e->arg_s32[0]);
    }
    return 0;
}

static int handle_exit_umount(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit umount: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit umount: success, %s, ret=%lld\n",
                task_info, e->ret);
    }
    return 0;
}

static int handle_enter_move_mount(const struct event_t *e, const char *task_info) {
    if (e->is_valid == true) {
        printf("Enter move_mount: %s, from_fd=%d, from_pathname=%s, to_fd=%d, to_pathname=%s, flags=%llu\n",
                task_info, e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2, e->arg_u64[0]);
    } else {
        printf("Enter move_mount: %s, from_fd=%d, to_fd=%d, failed to read from_fd, from_pathname, to_fd, to_pathname, flags=%llu\n",
                task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u64[0]);
    }
    return 0;
}

static int handle_exit_move_mount(const struct event_t *e, const char *task_info) {
    if (e->ret < 0) {
        printf("Exit move_mount: failed, %s, error_code=%lld\n",
                task_info, e->ret);
    } else {
        printf("Exit move_mount: success, %s, ret=%lld\n",
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
    event_handler[__NR_close].enter = handle_enter_close;
    event_handler[__NR_close].exit = handle_exit_close;
    event_handler[__NR_creat].enter = handle_enter_creat;
    event_handler[__NR_creat].exit = handle_exit_creat;
    event_handler[__NR_open].enter = handle_enter_open;
    event_handler[__NR_open].exit = handle_exit_open;
    event_handler[__NR_openat].enter = handle_enter_openat;
    event_handler[__NR_openat].exit = handle_exit_openat;
    event_handler[__NR_openat2].enter = handle_enter_openat2;
    event_handler[__NR_openat2].exit = handle_exit_openat2;
    event_handler[__NR_name_to_handle_at].enter = handle_enter_name_to_handle_at;
    event_handler[__NR_name_to_handle_at].exit = handle_exit_name_to_handle_at;
    event_handler[__NR_open_by_handle_at].enter = handle_enter_open_by_handle_at;
    event_handler[__NR_open_by_handle_at].exit = handle_exit_open_by_handle_at;
    event_handler[__NR_memfd_create].enter = handle_enter_memfd_create;
    event_handler[__NR_memfd_create].exit = handle_exit_memfd_create;
    event_handler[__NR_mknod].enter = handle_enter_mknod;
    event_handler[__NR_mknod].exit = handle_exit_mknod;
    event_handler[__NR_mknodat].enter = handle_enter_mknodat;
    event_handler[__NR_mknodat].exit = handle_exit_mknodat;
    event_handler[__NR_rename].enter = handle_enter_rename;
    event_handler[__NR_rename].exit = handle_exit_rename;
    event_handler[__NR_renameat].enter = handle_enter_renameat;
    event_handler[__NR_renameat].exit = handle_exit_renameat;
    event_handler[__NR_renameat2].enter = handle_enter_renameat2;
    event_handler[__NR_renameat2].exit = handle_exit_renameat2;
    event_handler[__NR_truncate].enter = handle_enter_truncate;
    event_handler[__NR_truncate].exit = handle_exit_truncate;
    event_handler[__NR_ftruncate].enter = handle_enter_ftruncate;
    event_handler[__NR_ftruncate].exit = handle_exit_ftruncate;
    event_handler[__NR_fallocate].enter = handle_enter_fallocate;
    event_handler[__NR_fallocate].exit = handle_exit_fallocate;
    event_handler[__NR_mkdir].enter = handle_enter_mkdir;
    event_handler[__NR_mkdir].exit = handle_exit_mkdir;
    event_handler[__NR_mkdirat].enter = handle_enter_mkdirat;
    event_handler[__NR_mkdirat].exit = handle_exit_mkdirat;
    event_handler[__NR_rmdir].enter = handle_enter_rmdir;
    event_handler[__NR_rmdir].exit = handle_exit_rmdir;
    event_handler[__NR_getcwd].enter = handle_enter_getcwd;
    event_handler[__NR_getcwd].exit = handle_exit_getcwd;
    event_handler[__NR_chdir].enter = handle_enter_chdir;
    event_handler[__NR_chdir].exit = handle_exit_chdir;
    event_handler[__NR_fchdir].enter = handle_enter_fchdir;
    event_handler[__NR_fchdir].exit = handle_exit_fchdir;
    event_handler[__NR_chroot].enter = handle_enter_chroot;
    event_handler[__NR_chroot].exit = handle_exit_chroot;
    event_handler[__NR_pivot_root].enter = handle_enter_pivot_root;
    event_handler[__NR_pivot_root].exit = handle_exit_pivot_root;
    event_handler[__NR_getdents].enter = handle_enter_getdents;
    event_handler[__NR_getdents].exit = handle_exit_getdents;
    event_handler[__NR_getdents64].enter = handle_enter_getdents64;
    event_handler[__NR_getdents64].exit = handle_exit_getdents64;
    event_handler[__NR_link].enter = handle_enter_link;
    event_handler[__NR_link].exit = handle_exit_link;
    event_handler[__NR_linkat].enter = handle_enter_linkat;
    event_handler[__NR_linkat].exit = handle_exit_linkat;
    event_handler[__NR_symlink].enter = handle_enter_symlink;
    event_handler[__NR_symlink].exit = handle_exit_symlink;
    event_handler[__NR_symlinkat].enter = handle_enter_symlinkat;
    event_handler[__NR_symlinkat].exit = handle_exit_symlinkat;
    event_handler[__NR_unlink].enter = handle_enter_unlink;
    event_handler[__NR_unlink].exit = handle_exit_unlink;
    event_handler[__NR_unlinkat].enter = handle_enter_unlinkat;
    event_handler[__NR_unlinkat].exit = handle_exit_unlinkat;
    event_handler[__NR_readlink].enter = handle_enter_readlink;
    event_handler[__NR_readlink].exit = handle_exit_readlink;
    event_handler[__NR_readlinkat].enter = handle_enter_readlinkat;
    event_handler[__NR_readlinkat].exit = handle_exit_readlinkat;
    event_handler[__NR_umask].enter = handle_enter_umask;
    event_handler[__NR_umask].exit = handle_exit_umask;
    event_handler[__NR_stat].enter = handle_enter_newstat;
    event_handler[__NR_stat].exit = handle_exit_newstat;
    event_handler[__NR_lstat].enter = handle_enter_newlstat;
    event_handler[__NR_lstat].exit = handle_exit_newlstat;
    event_handler[__NR_fstat].enter = handle_enter_newfstat;
    event_handler[__NR_fstat].exit = handle_exit_newfstat;
    event_handler[__NR_newfstatat].enter = handle_enter_newfstatat;
    event_handler[__NR_newfstatat].exit = handle_exit_newfstatat;
    event_handler[__NR_statx].enter = handle_enter_statx;
    event_handler[__NR_statx].exit = handle_exit_statx;
    event_handler[__NR_statfs].enter = handle_enter_statfs;
    event_handler[__NR_statfs].exit = handle_exit_statfs;
    event_handler[__NR_fstatfs].enter = handle_enter_fstatfs;
    event_handler[__NR_fstatfs].exit = handle_exit_fstatfs;
    event_handler[__NR_chmod].enter = handle_enter_chmod;
    event_handler[__NR_chmod].exit = handle_exit_chmod;
    event_handler[__NR_fchmod].enter = handle_enter_fchmod;
    event_handler[__NR_fchmod].exit = handle_exit_fchmod;
    event_handler[__NR_fchmodat].enter = handle_enter_fchmodat;
    event_handler[__NR_fchmodat].exit = handle_exit_fchmodat;
    event_handler[__NR_chown].enter = handle_enter_chown;
    event_handler[__NR_chown].exit = handle_exit_chown;
    event_handler[__NR_lchown].enter = handle_enter_lchown;
    event_handler[__NR_lchown].exit = handle_exit_lchown;
    event_handler[__NR_fchown].enter = handle_enter_fchown;
    event_handler[__NR_fchown].exit = handle_exit_fchown;
    event_handler[__NR_fchownat].enter = handle_enter_fchownat;
    event_handler[__NR_fchownat].exit = handle_exit_fchownat;
    event_handler[__NR_utime].enter = handle_enter_utime;
    event_handler[__NR_utime].exit = handle_exit_utime;
    event_handler[__NR_utimes].enter = handle_enter_utimes;
    event_handler[__NR_utimes].exit = handle_exit_utimes;
    event_handler[__NR_futimesat].enter = handle_enter_futimesat;
    event_handler[__NR_futimesat].exit = handle_exit_futimesat;
    event_handler[__NR_utimensat].enter = handle_enter_utimensat;
    event_handler[__NR_utimensat].exit = handle_exit_utimensat;
    event_handler[__NR_access].enter = handle_enter_access;
    event_handler[__NR_access].exit = handle_exit_access;
    event_handler[__NR_faccessat].enter = handle_enter_faccessat;
    event_handler[__NR_faccessat].exit = handle_exit_faccessat;
    event_handler[__NR_setxattr].enter = handle_enter_setxattr;
    event_handler[__NR_setxattr].exit = handle_exit_setxattr;
    event_handler[__NR_lsetxattr].enter = handle_enter_lsetxattr;
    event_handler[__NR_lsetxattr].exit = handle_exit_lsetxattr;
    event_handler[__NR_fsetxattr].enter = handle_enter_fsetxattr;
    event_handler[__NR_fsetxattr].exit = handle_exit_fsetxattr;
    event_handler[__NR_getxattr].enter = handle_enter_getxattr;
    event_handler[__NR_getxattr].exit = handle_exit_getxattr;
    event_handler[__NR_lgetxattr].enter = handle_enter_lgetxattr;
    event_handler[__NR_lgetxattr].exit = handle_exit_lgetxattr;
    event_handler[__NR_fgetxattr].enter = handle_enter_fgetxattr;
    event_handler[__NR_fgetxattr].exit = handle_exit_fgetxattr;
    event_handler[__NR_listxattr].enter = handle_enter_listxattr;
    event_handler[__NR_listxattr].exit = handle_exit_listxattr;
    event_handler[__NR_llistxattr].enter = handle_enter_llistxattr;
    event_handler[__NR_llistxattr].exit = handle_exit_llistxattr;
    event_handler[__NR_flistxattr].enter = handle_enter_flistxattr;
    event_handler[__NR_flistxattr].exit = handle_exit_flistxattr;
    event_handler[__NR_removexattr].enter = handle_enter_removexattr;
    event_handler[__NR_removexattr].exit = handle_exit_removexattr;
    event_handler[__NR_lremovexattr].enter = handle_enter_lremovexattr;
    event_handler[__NR_lremovexattr].exit = handle_exit_lremovexattr;
    event_handler[__NR_fremovexattr].enter = handle_enter_fremovexattr;
    event_handler[__NR_fremovexattr].exit = handle_exit_fremovexattr;
    event_handler[__NR_fcntl].enter = handle_enter_fcntl;
    event_handler[__NR_fcntl].exit = handle_exit_fcntl;
    event_handler[__NR_dup].enter = handle_enter_dup;
    event_handler[__NR_dup].exit = handle_exit_dup;
    event_handler[__NR_dup2].enter = handle_enter_dup2;
    event_handler[__NR_dup2].exit = handle_exit_dup2;
    event_handler[__NR_dup3].enter = handle_enter_dup3;
    event_handler[__NR_dup3].exit = handle_exit_dup3;
    event_handler[__NR_flock].enter = handle_enter_flock;
    event_handler[__NR_flock].exit = handle_exit_flock;
    event_handler[__NR_read].enter = handle_enter_read;
    event_handler[__NR_read].exit = handle_exit_read;
    event_handler[__NR_pread64].enter = handle_enter_pread64;
    event_handler[__NR_pread64].exit = handle_exit_pread64;
    event_handler[__NR_readv].enter = handle_enter_readv;
    event_handler[__NR_readv].exit = handle_exit_readv;
    event_handler[__NR_preadv].enter = handle_enter_preadv;
    event_handler[__NR_preadv].exit = handle_exit_preadv;
    event_handler[__NR_preadv2].enter = handle_enter_preadv2;
    event_handler[__NR_preadv2].exit = handle_exit_preadv2;
    event_handler[__NR_write].enter = handle_enter_write;
    event_handler[__NR_write].exit = handle_exit_write;
    event_handler[__NR_pwrite64].enter = handle_enter_pwrite64;
    event_handler[__NR_pwrite64].exit = handle_exit_pwrite64;
    event_handler[__NR_writev].enter = handle_enter_writev;
    event_handler[__NR_writev].exit = handle_exit_writev;
    event_handler[__NR_pwritev].enter = handle_enter_pwritev;
    event_handler[__NR_pwritev].exit = handle_exit_pwritev;
    event_handler[__NR_pwritev2].enter = handle_enter_pwritev2;
    event_handler[__NR_pwritev2].exit = handle_exit_pwritev2;
    event_handler[__NR_lseek].enter = handle_enter_lseek;
    event_handler[__NR_lseek].exit = handle_exit_lseek;
    event_handler[__NR_sendfile].enter = handle_enter_sendfile64;
    event_handler[__NR_sendfile].exit = handle_exit_sendfile64;
    event_handler[__NR_inotify_init].enter = handle_enter_inotify_init;
    event_handler[__NR_inotify_init].exit = handle_exit_inotify_init;
    event_handler[__NR_inotify_init1].enter = handle_enter_inotify_init1;
    event_handler[__NR_inotify_init1].exit = handle_exit_inotify_init1;
    event_handler[__NR_inotify_add_watch].enter = handle_enter_inotify_add_watch;
    event_handler[__NR_inotify_add_watch].exit = handle_exit_inotify_add_watch;
    event_handler[__NR_inotify_rm_watch].enter = handle_enter_inotify_rm_watch;
    event_handler[__NR_inotify_rm_watch].exit = handle_exit_inotify_rm_watch;
    event_handler[__NR_fanotify_init].enter = handle_enter_fanotify_init;
    event_handler[__NR_fanotify_init].exit = handle_exit_fanotify_init;
    event_handler[__NR_fanotify_mark].enter = handle_enter_fanotify_mark;
    event_handler[__NR_fanotify_mark].exit = handle_exit_fanotify_mark;
    event_handler[__NR_mount].enter = handle_enter_mount;
    event_handler[__NR_mount].exit = handle_exit_mount;
    event_handler[__NR_umount2].enter = handle_enter_umount;
    event_handler[__NR_umount2].exit = handle_exit_umount;
    event_handler[__NR_move_mount].enter = handle_enter_move_mount;
    event_handler[__NR_move_mount].exit = handle_exit_move_mount;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = (struct event_t *)data;
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