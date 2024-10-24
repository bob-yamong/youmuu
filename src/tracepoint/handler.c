#include "handler.h"

#define MAX_EVENT_ID 4096

static void get_task_info_str(const struct current_task *task, char *buffer, size_t buffer_size) {
    struct sysinfo si;
    char timestamp[26];
    time_t current_time, boot_time, timer, actual_time;

    current_time = time(NULL);
    if (sysinfo(&si) != 0) {
        snprintf(buffer, buffer_size, "Error getting system info");
        return;
    }
    boot_time = current_time - si.uptime;
    timer = task->timestamp / 1000000000;
    unsigned long long nanoseconds = task->timestamp % 1000000000;
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

static struct socket_handlers event_handler[MAX_EVENT_ID] = {0};

static void init_event_handlers(void) {
    event_handler[41].enter = handle_enter_socket;
    event_handler[41].exit = handle_exit_socket;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    static bool initialized = false;
    if (!initialized) {
        init_event_handlers();
        initialized = true;
    }

    const struct event_t *e = data;
    char task_info[256];
    get_task_info_str(&e->task, task_info, sizeof(task_info));
    
    struct socket_handlers *handlers = &event_handler[e->event_id];
    event_handler_t handler = e->is_enter ? handlers->enter : handlers->exit;
    if (handler) {
        return handler(e, task_info);
    }
    
    printf("Unknown event: %s, event_id=%lld\n", task_info, e->event_id);
    return 0;
}

// int handle_event(void *ctx, void *data, size_t data_sz) {
//     const struct event_t *e = data;
//     char task_info[256];
//     get_task_info_str(&e->task, task_info, sizeof(task_info));
    
//     switch(e->event_id) {
//         case SYS_ENTER_SOCKET:
//             printf("Enter socket: %s, domain=%d, type=%d, protocol=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             break;
//         case SYS_EXIT_SOCKET:
//             if (e->ret < 0) {
//                 printf("Exit socket: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit socket: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SOCKETPAIR:
//             printf("Enter socketpair: %s, domain=%d, type=%d, protocol=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             break;
//         case SYS_EXIT_SOCKETPAIR:
//             if (e->ret < 0) {
//                 printf("Exit socketpair: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit socketpair: success, %s, sv[0]=%d, sv[1]=%d, ret=%lld\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], e->ret);
//             } else {
//                 printf("Exit socketpair: success but failed to read socket values, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SETSOCKOPT:
//             if (e->is_valid == true) {
//                 printf("Enter setsockopt: %s, socktfd=%d, level=%d, optname=%d, optval=%u, optlen=%d\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_u32[0], e->arg_s32[3]);
//             } else {
//                 printf("Enter setsockopt: %s, socktfd=%d, level=%d, optname=%d, failed to read optval, optlen=%d\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_s32[3]);
//             }
//             break;
//         case SYS_EXIT_SETSOCKOPT:
//             if (e->ret < 0) {
//                 printf("Exit setsockopt: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit setsockopt: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_GETSOCKOPT:
//             printf("Enter getsockopt: %s, socketfd=%d, level=%d, optname=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             break;
//         case SYS_EXIT_GETSOCKOPT:
//             if (e->ret < 0) {
//                 printf("Exit getsockopt: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit getsockopt: success, %s, optval=%u, optlen=%u, ret=%lld\n",
//                         task_info, e->arg_u32[0], e->arg_u32[1], e->ret);
//             } else {
//                 printf("Exit getsockopt: success, %s, failed to read optval, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_GETSOCKNAME:
//             printf("Enter getsockname: %s, socketfd=%d\n",
//                     task_info, e->arg_s32[0]);
//             break;
//         case SYS_EXIT_GETSOCKNAME:
//             if (e->ret < 0) {
//                 printf("Exit getsockname: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit getsockname: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit getsockname: success, %s, failed to read socket address info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_GETPEERNAME:
//             printf("Enter getpeername: %s, socketfd=%d\n",
//                     task_info, e->arg_s32[0]);
//             break;
//         case SYS_EXIT_GETPEERNAME:
//             if (e->ret < 0) {
//                 printf("Exit getpeername: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit getpeername: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit getpeername: success, %s, failed to read socket address info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_BIND:
//             if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Enter bind: %s, socktfd=%d, addr=%s:%u, ip_version=%s\n",
//                         task_info, e->arg_s32[0], ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
//             } else {
//                 printf("Enter bind: %s, socktfd=%d, failed to read address info\n",
//                         task_info, e->arg_s32[0]);
//             }
//             break;
//         case SYS_EXIT_BIND:
//             if (e->ret < 0) {
//                 printf("Exit bind: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit bind: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_LISTEN:
//             printf("Enter listen: %s, socktfd=%d, backlog=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_LISTEN:
//             if (e->ret < 0) {
//                 printf("Exit listen: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit listen: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_ACCEPT:
//             printf("Enter accept: %s, socktfd=%d\n",
//                     task_info, e->arg_s32[0]);
//             break;
//         case SYS_EXIT_ACCEPT:
//             if (e->ret < 0) {
//                 printf("Exit accept: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_null == true) {
//                 printf("Exit accept: success, %s, socket address info is not requested, ret=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit accept: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit accept: success, %s, failed to read socket address info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_ACCEPT4:
//             printf("Enter accept4: %s, socktfd=%d, flags=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_ACCEPT4:
//             if (e->ret < 0) {
//                 printf("Exit accept4: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_null == true) {
//                 printf("Exit accept4: success, %s, socket address info is not requested, ret=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit accept4: success, %s, address=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit accept4: success, %s, failed to read socket address info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_CONNECT:
//             if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Enter connect: %s, socketfd=%d, addr=%s:%u, ip_version=%s\n",
//                         task_info, e->arg_s32[0], ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
//             } else {
//                 printf("Enter connect: %s, socketfd=%d, failed to read address info\n",
//                         task_info, e->arg_s32[0]);
//             }
//             break;
//         case SYS_EXIT_CONNECT:
//             if (e->ret < 0) {
//                 printf("Exit connect: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit connect: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SHUTDOWN:
//             printf("Enter shutdown: %s, socketfd=%d, how=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_SHUTDOWN:
//             if (e->ret < 0) {
//                 printf("Exit shutdown: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit shutdown: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_RECVFROM:
//             printf("Enter recvfrom: %s, socktfd=%d, msg_len=%llu, flags=%d\n",
//                     task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_RECVFROM:
//             if (e->ret < 0) {
//                 printf("Exit recvfrom: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_null == true) {
//                 printf("Exit recvfrom: success, %s, socket address info is not requested, ret=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit recvfrom: success, %s, src_addr=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit recvfrom: success, %s, failed to read source info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_RECVMSG:
//             printf("Enter recvmsg: %s, socktfd=%d, msg_len=%llu, flags=%d\n",
//                     task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_RECVMSG:
//             if (e->ret < 0) {
//                 printf("Exit recvmsg: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Exit recvmsg: success, %s, src_addr=%s:%u, ip_version=%s, ret=%lld\n",
//                         task_info, ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown", e->ret);
//             } else {
//                 printf("Exit recvmsg: success, %s, failed to read source info, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_RECVMMSG:
//             printf("Enter recvmmsg: %s, socktfd=%d, vlen=%u, flags=%d\n",
//                     task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_RECVMMSG:
//             if (e->ret < 0) {
//                 printf("Exit recvmmsg: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit recvmmsg: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SENDTO:
//             if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Enter sendto: %s, socktfd=%d, msg_len=%llu, flags=%d, dest_addr=%s:%u, ip_version=%s\n",
//                         task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1], ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
//             } else {
//                 printf("Enter sendto: %s, socktfd=%d, msg_len=%llu, flags=%d, failed to read destination info\n",
//                         task_info, e->arg_s32[0], e->arg_u64[0], e->arg_s32[1]);
//             }
//             break;
//         case SYS_EXIT_SENDTO:
//             if (e->ret < 0) {
//                 printf("Exit sendto: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit sendto: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SENDMSG:
//             if (e->is_valid == true) {
//                 char ip_str[INET6_ADDRSTRLEN] = {0};
//                 if (e->addr_family == AF_INET) {
//                     inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
//                 } else if (e->addr_family == AF_INET6) {
//                     inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
//                 }
//                 printf("Enter sendmsg: %s, socktfd=%d, flags=%d, dest_addr=%s:%u, ip_version=%s\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], ip_str, e->port, 
//                         e->addr_family == AF_INET ? "IPv4" : e->addr_family == AF_INET6 ? "IPv6" : "Unknown");
//             } else {
//                 printf("Enter sendmsg: %s, socktfd=%d, flags=%d, failed to read destination info\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1]);
//             }
//             break;
//         case SYS_EXIT_SENDMSG:
//             if (e->ret < 0) {
//                 printf("Exit sendmsg: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit sendmsg: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SENDMMSG:
//             printf("Enter sendmmsg: %s, socktfd=%d, vlen=%u, flags=%d\n",
//                     task_info, e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//             break;
//         case SYS_EXIT_SENDMMSG:
//             if (e->ret < 0) {
//                 printf("Exit sendmmsg: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit sendmmsg: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SETHOSTNAME:
//             if (e->is_valid == true) {
//                 printf("Enter sethostname: %s, hostname=%s, len=%llu\n",
//                         task_info, e->arg_str, e->arg_u64[0]);
//             } else {
//                 printf("Enter sethostname: %s, failed to read hostname, len=%llu\n",
//                         task_info, e->arg_u64[0]);
//             }
//             break;
//         case SYS_EXIT_SETHOSTNAME:
//             if (e->ret < 0) {
//                 printf("Exit sethostname: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit sethostname: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_SETDOMAINNAME:
//             if (e->is_valid == true) {
//                 printf("Enter setdomainname: %s, domainname=%s, len=%llu\n",
//                         task_info, e->arg_str, e->arg_u64[0]);
//             } else {
//                 printf("Enter setdomainname: %s, failed to read domainname, len=%llu\n",
//                         task_info, e->arg_u64[0]);
//             }
//             break;
//         case SYS_EXIT_SETDOMAINNAME:
//             if (e->ret < 0) {
//                 printf("Exit setdomainname: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit setdomainname: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_IOCTL:
//             printf("Enter ioctl: %s, fd=%d, op=%llu\n",
//                     task_info, e->arg_s32[0], e->arg_u64[0]);
//             break;
//         case SYS_EXIT_IOCTL:
//             if (e->ret < 0) {
//                 printf("Exit ioctl: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit ioctl: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_POLL:
//             if (e->is_valid == true) {
//                 printf("Enter poll: %s, nfds=%llu, timeout=%d, pollfd=%d, event=%d\n",
//                         task_info, e->arg_u64[0], e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             } else {
//                 printf("Enter poll: %s, nfds=%llu, timeout=%d, failed to read pollfd array\n",
//                         task_info, e->arg_u64[0], e->arg_s32[0]);
//             }
//             break;
//         case SYS_EXIT_POLL:
//             if (e->ret < 0) {
//                 printf("Exit poll: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit poll: success, %s, revents=%d, ret=%llu\n",
//                         task_info, e->arg_s32[0], e->ret);
//             } else {
//                 printf("Exit poll: success, %s, failed to read revents, ret=%llu\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_PPOLL:
//             if (e->is_valid) {
//                 if (e->arg_u64[1] == 999999999) {
//                     printf("Enter ppoll: %s, nfds=%llu, timeout=infinite, pollfd=%d, event=%d\n",
//                             task_info, e->arg_u64[0], e->arg_s32[1], e->arg_s32[2]);
//                 } else {
//                     printf("Enter ppoll: %s, nfds=%llu, timeout=%llu.%09llu, pollfd=%d, event=%d\n",
//                             task_info, e->arg_u64[0], e->arg_u64[1], e->arg_u64[2],
//                             e->arg_s32[1], e->arg_s32[2]);
//                 }
//             } else {
//                 printf("Enter ppoll: %s, nfds=%llu, failed to read pollfd array\n",
//                         task_info, e->arg_u64[0]);
//             }
//             break;
//         case SYS_EXIT_PPOLL:
//             if (e->ret < 0) {
//                 printf("Exit ppoll: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit ppoll: success, %s, revents=%d, ret=%lld\n",
//                         task_info, e->arg_s32[0], e->ret);
//             } else {
//                 printf("Exit ppoll: success, %s, failed to read revents, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_CREATE:
//             printf("Enter epoll_create: %s, size=%d\n",
//                     task_info, e->arg_s32[0]);
//             break;
//         case SYS_EXIT_EPOLL_CREATE:
//             if (e->ret < 0) {
//                 printf("Exit epoll_create: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit epoll_create: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_CREATE1:
//             printf("Enter epoll_create1: %s, flags=%d\n",
//                     task_info, e->arg_s32[0]);
//             break;
//         case SYS_EXIT_EPOLL_CREATE1:
//             if (e->ret < 0) {
//                 printf("Exit epoll_create1: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit epoll_create1: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_CTL:
//             if (e->is_valid == true) {
//                 printf("Enter epoll_ctl: %s, epfd=%d, op=%d, fd=%d, event=%u, data=%llu\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_u32[0], e->arg_u64[0]);
//             } else {
//                 printf("Enter epoll_ctl: %s, epfd=%d, op=%d, failed to read event\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1]);
//             }
//             break;
//         case SYS_EXIT_EPOLL_CTL:
//             if (e->ret < 0) {
//                 printf("Exit epoll_ctl: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else {
//                 printf("Exit epoll_ctl: success, %s, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_WAIT:
//             printf("Enter epoll_wait: %s, epfd=%d, maxevents=%d, timeout=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             break;
//         case SYS_EXIT_EPOLL_WAIT:
//             if (e->ret < 0) {
//                 printf("Exit epoll_wait: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit epoll_wait: success, %s, events=%d, data=%llu, ret=%lld\n",
//                         task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
//             } else {
//                 printf("Exit epoll_wait: success, %s, failed to read revents, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_PWAIT:
//             printf("Enter epoll_pwait: %s, epfd=%d, maxevents=%d, timeout=%d\n",
//                     task_info, e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//             break;
//         case SYS_EXIT_EPOLL_PWAIT:
//             if (e->ret < 0) {
//                 printf("Exit epoll_pwait: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit epoll_pwait: success, %s, events=%d, data=%llu, ret=%lld\n",
//                         task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
//             } else {
//                 printf("Exit epoll_pwait: success, %s, failed to read revents, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         case SYS_ENTER_EPOLL_PWAIT2:
//             if (e->arg_u64[0] == 999999999) {
//                 printf("Enter epoll_pwait2: %s, epfd=%d, maxevents=%d, timeout=infinite\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1]);
//             } else {
//                 printf("Enter epoll_pwait2: %s, epfd=%d, maxevents=%d, timeout=%llu.%09llu\n",
//                         task_info, e->arg_s32[0], e->arg_s32[1], e->arg_u64[0], e->arg_u64[1]);
//             }
//             break;
//         case SYS_EXIT_EPOLL_PWAIT2:
//             if (e->ret < 0) {
//                 printf("Exit epoll_pwait2: failed, %s, error_code=%lld\n",
//                         task_info, e->ret);
//             } else if (e->is_valid == true) {
//                 printf("Exit epoll_pwait2: success, %s, events=%d, data=%llu, ret=%lld\n",
//                         task_info, e->arg_s32[0], e->arg_u64[0], e->ret);
//             } else {
//                 printf("Exit epoll_pwait2: success, %s, failed to read revents, ret=%lld\n",
//                         task_info, e->ret);
//             }
//             break;
//         default:
//             printf("Unknown event: %s, event_id=%d\n",
//                     task_info, e->event_id);
//     }
    
//     return 0;
// }