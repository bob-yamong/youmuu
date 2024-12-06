#include "handler.h"

#define NANOSECONDS_IN_A_SECOND 1000000000
#define MAX_EVENT_ID 1024

time_t boot_time;

static db_event_t get_str(const struct current_task *task, time_t boot_time)
{
    db_event_t event;
    time_t timer, actual_time;

    unsigned long long nanoseconds = task->timestamp % NANOSECONDS_IN_A_SECOND;
    timer = task->timestamp / NANOSECONDS_IN_A_SECOND;
    actual_time = boot_time + timer;

    event.timestamp = std::chrono::system_clock::from_time_t(actual_time) +
                      std::chrono::nanoseconds(nanoseconds / 1000);
    event.syscall = task->event_id;
    event.pid_namespace = task->pid_namespace;
    event.mnt_namespace = task->mnt_namespace;
    auto it = std::find_if(ContainerManager::containers.begin(), ContainerManager::containers.end(),
                           [&](const ContainerInfo &container)
                           {
                               return container.ns_id == task->pid_namespace; // ns_id 비교
                           });

    if (it != ContainerManager::containers.end())
    {
        // 일치하는 ns_id가 있는 경우
        event.container_name = it->name;
    }
    else
    {
        // 일치하는 ns_id가 없는 경우
        event.container_name = "Unknown";
    }

    event.ppid = task->ppid;
    event.pid = task->pid;
    event.tid = task->tid;
    event.uid = task->uid;
    event.gid = task->gid;
    event.comm = std::string(reinterpret_cast<const char *>(task->comm));

    return event;
}

typedef int (*event_handler_t)(const struct event_t *e, const db_event_t &base_event);

static void get_ip_str(const struct event_t *e, char *ip_str, size_t str_len)
{
    memset(ip_str, 0, str_len);

    if (e->addr_family == AF_INET)
    {
        inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN);
    }
    else if (e->addr_family == AF_INET6)
    {
        inet_ntop(AF_INET6, e->ipv6_addr, ip_str, INET6_ADDRSTRLEN);
    }
}

static void add_event(const db_event_t &event)
{
    if (eventLogger)
    {
        eventLogger->addEvent(event);
    }
    else
    {
        std::cerr << "EventLogger가 초기화되지 않았습니다.\n";
    }
}

struct socket_handlers
{
    event_handler_t enter;
    event_handler_t exit;
};

static int handle_enter_socket(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // domain
    event.arg1 = std::to_string(e->arg_s32[1]); // type
    event.arg2 = std::to_string(e->arg_s32[2]); // protocol
    add_event(event);
    return 0;
}

static int handle_exit_socket(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_socketpair(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // domain
    event.arg1 = std::to_string(e->arg_s32[1]); // type
    event.arg2 = std::to_string(e->arg_s32[2]); // protocol
    add_event(event);
    return 0;
}

static int handle_exit_socketpair(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_s32[0]); // sv[0]
        event.arg1 = std::to_string(e->arg_s32[1]); // sv[1]
    }
    add_event(event);
    return 0;
}

static int handle_enter_setsockopt(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // level
    event.arg2 = std::to_string(e->arg_s32[2]); // optname
    event.arg4 = std::to_string(e->arg_s32[3]); // optlen
    if (e->is_valid)
    {
        event.arg3 = std::to_string(e->arg_u32[0]); // optval
    }
    add_event(event);
    return 0;
}

static int handle_exit_setsockopt(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getsockopt(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // level
    event.arg2 = std::to_string(e->arg_s32[2]); // optname
    add_event(event);
    return 0;
}

static int handle_exit_getsockopt(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u32[0]); // optval
        event.arg1 = std::to_string(e->arg_u32[1]); // optlen
    }
    add_event(event);
    return 0;
}

static int handle_enter_getsockname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    add_event(event);
    return 0;
}

static int handle_exit_getsockname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_getpeername(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    add_event(event);
    return 0;
}

static int handle_exit_getpeername(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_bind(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_exit_bind(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_listen(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // backlog
    add_event(event);
    return 0;
}

static int handle_exit_listen(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_accept(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    add_event(event);
    return 0;
}

static int handle_exit_accept(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null)
    {
        event.arg0 = "socket address info is not requested";
    }
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_accept4(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_accept4(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null)
    {
        event.arg0 = "socket address info is not requested";
    }
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_connect(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_exit_connect(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_shutdown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // how
    add_event(event);
    return 0;
}

static int handle_exit_shutdown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_recvfrom(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // msg_len
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_recvfrom(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null)
    {
        event.arg0 = "socket address info is not requested";
    }
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;                         // ip
        event.arg1 = std::to_string(e->port);        // port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_recvmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_recvmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = std::string(ip_str);            // src_addr
        event.arg1 = std::to_string(e->port);        // src_port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_enter_recvmmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // vlen
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_recvmmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sendto(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // msg_len
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg3 = std::string(ip_str);            // dest_addr
        event.arg4 = std::to_string(e->port);        // dest_port
        event.arg5 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_exit_sendto(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sendmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg2 = std::string(ip_str);            // dest_addr
        event.arg3 = std::to_string(e->port);        // dest_port
        event.arg4 = std::to_string(e->addr_family); // ip_version
    }
    add_event(event);
    return 0;
}

static int handle_exit_sendmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sendmmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // vlen
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_sendmmsg(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sethostname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // hostname
    }
    add_event(event);
    return 0;
}

static int handle_exit_sethostname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setdomainname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // domainname
    }
    add_event(event);
    return 0;
}

static int handle_exit_setdomainname(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_ioctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // op
    add_event(event);
    return 0;
}

static int handle_exit_ioctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_close(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    add_event(event);
    return 0;
}

static int handle_exit_close(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_creat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_creat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_open(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_s32[0]); // flags
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_open(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_openat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[1]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // flags
    event.arg3 = std::to_string(e->arg_u32[1]); // mode
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_openat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_openat2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg5 = std::to_string(e->arg_u64[0]); // size
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
        event.arg2 = std::to_string(e->arg_u64[1]);                           // flags
        event.arg3 = std::to_string(e->arg_u64[2]);                           // mode
        event.arg4 = std::to_string(e->arg_u64[3]);                           // resolve
    }
    add_event(event);
    return 0;
}

static int handle_exit_openat2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

// static int handle_enter_name_to_handle_at(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
//     event.arg5 = std::to_string(e->arg_s32[1]); // flags
//     if (e->is_valid) {
//         event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
//         event.arg2 = std::to_string(e->arg_u32[0]); // hadle_bytes
//         event.arg3 = std::to_string(e->arg_s32[3]); // handle_type
//         event.arg4 = std::to_string(e->arg_s32[2]); // mount_id
//     }
//     add_event(event);
//     return 0;
// }

// static int handle_exit_name_to_handle_at(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.ret = e->ret;
//     add_event(event);
//     return 0;
// }

// static int handle_enter_open_by_handle_at(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.arg0 = std::to_string(e->arg_s32[0]); // mount_fd
//     event.arg3 = std::to_string(e->arg_s32[1]); // flags
//     if (e->is_valid) {
//         event.arg1 = std::to_string(e->arg_u32[0]); // handle_bytes
//         event.arg2 = std::to_string(e->arg_s32[2]); // handle_type
//     }
//     add_event(event);
//     return 0;
// }

// static int handle_exit_open_by_handle_at(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.ret = e->ret;
//     add_event(event);
//     return 0;
// }

static int handle_enter_memfd_create(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // name
    }
    add_event(event);
    return 0;
}

static int handle_exit_memfd_create(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mknod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    event.arg2 = std::to_string(e->arg_u64[0]); // dev
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_mknod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mknodat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    event.arg3 = std::to_string(e->arg_u64[0]); // dev
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_mknodat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_rename(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str));  // oldpath
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // newpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_rename(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_renameat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // olddirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // newdirfd
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str));  // oldpath
        event.arg3 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // newpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_renameat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_renameat2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[1]); // olddirfd
    event.arg2 = std::to_string(e->arg_s32[2]); // newdirfd
    event.arg4 = std::to_string(e->arg_u64[0]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str));  // oldpath
        event.arg3 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // newpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_renameat2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_truncate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u64[0]); // length
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_truncate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_ftruncate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // length
    add_event(event);
    return 0;
}

static int handle_exit_ftruncate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fallocate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // mode
    event.arg2 = std::to_string(e->arg_u64[0]); // offset
    event.arg3 = std::to_string(e->arg_u64[1]); // len
    add_event(event);
    return 0;
}

static int handle_exit_fallocate(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mkdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_mkdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mkdirat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_mkdirat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_rmdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_rmdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getcwd(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // size
    add_event(event);
    return 0;
}

static int handle_exit_getcwd(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_chdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_chdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fchdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    add_event(event);
    return 0;
}

static int handle_exit_fchdir(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_chroot(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_chroot(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_pivot_root(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str));  // new_root
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // put_old
    }
    add_event(event);
    return 0;
}

static int handle_exit_pivot_root(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getdents(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // fd
    event.arg1 = std::to_string(e->arg_u32[1]); // count
    add_event(event);
    return 0;
}

static int handle_exit_getdents(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u64[0]); // data
    }
    add_event(event);
    return 0;
}

static int handle_enter_getdents64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // count
    add_event(event);
    return 0;
}

static int handle_exit_getdents64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u64[0]); // data
    }
    add_event(event);
    return 0;
}

static int handle_enter_link(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str));  // oldpath
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // newpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_link(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_linkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // olddirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // newdirfd
    event.arg4 = std::to_string(e->arg_u32[0]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str));  // oldpath
        event.arg3 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // newpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_linkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_symlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str));  // target
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // linkpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_symlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_symlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // newdirfd
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str));  // target
        event.arg2 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // linkpath
    }
    add_event(event);
    return 0;
}

static int handle_exit_symlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_unlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_unlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_unlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_unlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_readlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u64[0]); // size
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_readlink(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_readlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u64[0]); // size
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_readlinkat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_umask(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // mask
    add_event(event);
    return 0;
}

static int handle_exit_umask(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_newstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // filename
    }
    add_event(event);
    return 0;
}

static int handle_exit_newstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_newlstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // filename
    }
    add_event(event);
    return 0;
}

static int handle_exit_newlstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_newfstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    add_event(event);
    return 0;
}

static int handle_exit_newfstat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_newfstatat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_newfstatat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_statx(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // flags
    event.arg3 = std::to_string(e->arg_u32[1]); // mask
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_statx(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_statfs(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_statfs(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fstatfs(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    add_event(event);
    return 0;
}

static int handle_exit_fstatfs(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_chmod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_chmod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fchmod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    add_event(event);
    return 0;
}

static int handle_exit_fchmod(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fchmodat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    event.arg3 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_fchmodat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_chown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // owner
    event.arg2 = std::to_string(e->arg_u32[1]); // group
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_chown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_lchown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // owner
    event.arg2 = std::to_string(e->arg_u32[1]); // group
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_lchown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fchown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u32[0]); // owner
    event.arg2 = std::to_string(e->arg_u32[1]); // group
    add_event(event);
    return 0;
}

static int handle_exit_fchown(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fchownat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // owner
    event.arg3 = std::to_string(e->arg_u32[1]); // group
    event.arg4 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_fchownat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_access(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_access(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_faccessat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // mode
    event.arg3 = std::to_string(e->arg_s32[2]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_faccessat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fcntl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // cmd
    event.arg2 = std::to_string(e->arg_u64[1]); // arg
    add_event(event);
    return 0;
}

static int handle_exit_fcntl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_dup(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // oldfd
    add_event(event);
    return 0;
}

static int handle_exit_dup(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_dup2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // oldfd
    event.arg1 = std::to_string(e->arg_s32[1]); // newfd
    add_event(event);
    return 0;
}

static int handle_exit_dup2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_dup3(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // oldfd
    event.arg1 = std::to_string(e->arg_s32[1]); // newfd
    event.arg2 = std::to_string(e->arg_s32[2]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_dup3(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_flock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // operation
    add_event(event);
    return 0;
}

static int handle_exit_flock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_read(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // count
    add_event(event);
    return 0;
}

static int handle_exit_read(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_pread64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    add_event(event);
    return 0;
}

static int handle_exit_pread64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_readv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    add_event(event);
    return 0;
}

static int handle_exit_readv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_preadv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    add_event(event);
    return 0;
}

static int handle_exit_preadv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_preadv2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    event.arg3 = std::to_string(e->arg_s32[2]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_preadv2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_write(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // count
    add_event(event);
    return 0;
}

static int handle_exit_write(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_pwrite64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    add_event(event);
    return 0;
}

static int handle_exit_pwrite64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_writev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    add_event(event);
    return 0;
}

static int handle_exit_writev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_pwritev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    add_event(event);
    return 0;
}

static int handle_exit_pwritev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_pwritev2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // iov_count
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    event.arg3 = std::to_string(e->arg_s32[2]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_pwritev2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_lseek(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s64[0]); // offset
    event.arg2 = std::to_string(e->arg_s32[1]); // whence
    add_event(event);
    return 0;
}

static int handle_exit_lseek(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sendfile64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // out_fd
    event.arg1 = std::to_string(e->arg_s32[1]); // in_fd
    event.arg2 = std::to_string(e->arg_s64[0]); // offset
    event.arg3 = std::to_string(e->arg_u64[0]); // count
    add_event(event);
    return 0;
}

static int handle_exit_sendfile64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_inotify_init(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_inotify_init(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_inotify_init1(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_inotify_init1(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_inotify_add_watch(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg2 = std::to_string(e->arg_u32[0]); // mask
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_inotify_add_watch(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_inotify_rm_watch(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // wd
    add_event(event);
    return 0;
}

static int handle_exit_inotify_rm_watch(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fanotify_init(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // flags
    event.arg1 = std::to_string(e->arg_s32[1]); // event_f_flags
    add_event(event);
    return 0;
}

static int handle_exit_fanotify_init(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fanotify_mark(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fanotify_fd
    event.arg1 = std::to_string(e->arg_u32[0]); // flags
    event.arg2 = std::to_string(e->arg_u64[0]); // mask
    event.arg3 = std::to_string(e->arg_s32[1]); // dirfd
    if (e->is_null == false)
    {
        if (e->is_valid)
        {
            event.arg4 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
        }
    }
    if (e->is_null == true)
    {
        event.arg4 = "monitoring directory events";
    }
    add_event(event);
    return 0;
}

static int handle_exit_fanotify_mark(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg3 = std::to_string(e->arg_u64[0]); // mountflags
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str));         // source
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str2));        // target
        event.arg2 = std::string(reinterpret_cast<const char *>(e->filesystem_type)); // filesystemtype
    }
    add_event(event);
    return 0;
}

static int handle_exit_mount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_umount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u64[0]); // flags
    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // target
    }
    add_event(event);
    return 0;
}

static int handle_exit_umount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_move_mount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // from_fd
    event.arg2 = std::to_string(e->arg_s32[1]); // to_fd
    event.arg4 = std::to_string(e->arg_u64[0]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str));  // from_pathname
        event.arg3 = std::string(reinterpret_cast<const char *>(e->arg_str2)); // to_pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_move_mount(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_clone(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // fn_ptr
    event.arg1 = std::to_string(e->arg_s32[0]); // flags
    return 0;
}

static int handle_exit_clone(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_clone3(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u64[0]); // flags
        event.arg1 = std::to_string(e->arg_u64[1]); // stack
        event.arg2 = std::to_string(e->arg_u64[2]); // stack_size
        event.arg3 = std::to_string(e->arg_u64[3]); // cgroup
    }
    add_event(event);
    return 0;
}

static int handle_exit_clone3(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_fork(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_fork(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_vfork(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_vfork(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_execve(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    if (e->is_valid)
    {
        event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_execve(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_execveat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // pathname
    }
    add_event(event);
    return 0;
}

static int handle_exit_execveat(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_exit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // status
    add_event(event);
    return 0;
}

static int handle_exit_exit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_exit_group(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // status
    add_event(event);
    return 0;
}

static int handle_exit_exit_group(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_wait4(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    if (e->is_valid)
    {
        event.arg1 = std::to_string(e->arg_s32[1]); // status
        event.arg2 = std::to_string(e->arg_s32[0]); // options
    }
    add_event(event);
    return 0;
}

static int handle_exit_wait4(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_waitid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // idtype
    event.arg1 = std::to_string(e->arg_u32[0]); // pid
    event.arg4 = std::to_string(e->arg_s32[1]); // options
    if (e->is_valid)
    {
        event.arg2 = std::to_string(e->arg_s32[2]); // si_signo
        event.arg3 = std::to_string(e->arg_s32[3]); // si_code
    }
    add_event(event);
    return 0;
}

static int handle_exit_waitid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getpid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getpid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getppid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getppid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_gettid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_gettid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setsid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_setsid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getsid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    add_event(event);
    return 0;
}

static int handle_exit_getsid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setpgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_u32[1]); // pgid
    add_event(event);
    return 0;
}

static int handle_exit_setpgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getpgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    add_event(event);
    return 0;
}

static int handle_exit_getpgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getpgrp(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getpgrp(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // uid
    add_event(event);
    return 0;
}

static int handle_exit_setuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // gid
    add_event(event);
    return 0;
}

static int handle_exit_setgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setresuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // ruid
    event.arg1 = std::to_string(e->arg_u32[1]); // euid
    event.arg2 = std::to_string(e->arg_u32[2]); // suid
    add_event(event);
    return 0;
}

static int handle_exit_setresuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getresuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getresuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u32[0]); // ruid
        event.arg1 = std::to_string(e->arg_u32[1]); // euid
        event.arg2 = std::to_string(e->arg_u32[2]); // suid
    }
    add_event(event);
    return 0;
}

static int handle_enter_setresgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // rgid
    event.arg1 = std::to_string(e->arg_u32[1]); // egid
    event.arg2 = std::to_string(e->arg_u32[2]); // sgid
    add_event(event);
    return 0;
}

static int handle_exit_setresgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getresgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getresgid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u32[0]); // rgid
        event.arg1 = std::to_string(e->arg_u32[1]); // egid
        event.arg2 = std::to_string(e->arg_u32[2]); // sgid
    }
    add_event(event);
    return 0;
}

static int handle_enter_setreuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // ruid
    event.arg1 = std::to_string(e->arg_u32[1]); // euid
    add_event(event);
    return 0;
}

static int handle_exit_setreuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setregid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // rgid
    event.arg1 = std::to_string(e->arg_u32[1]); // egid
    add_event(event);
    return 0;
}

static int handle_exit_setregid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_geteuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_geteuid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getegid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_getegid(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setgroups(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // size
    add_event(event);
    return 0;
}

static int handle_exit_setgroups(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getgroups(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // size
    return 0;
}

static int handle_exit_getgroups(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setns(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // nstype
    add_event(event);
    return 0;
}

static int handle_exit_setns(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setrlimit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // resource
    if (e->is_valid)
    {
        event.arg1 = std::to_string(e->arg_u64[1]); // rlim_cur
        event.arg2 = std::to_string(e->arg_u64[2]); // rlim_max
    }
    add_event(event);
    return 0;
}

static int handle_exit_setrlimit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getrlimit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // resource
    add_event(event);
    return 0;
}

static int handle_exit_getrlimit(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u64[0]); // rlim_cur
        event.arg1 = std::to_string(e->arg_u64[1]); // rlim_max
    }
    return 0;
}

static int handle_enter_prlimit64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_s32[0]); // resource
    add_event(event);
    return 0;
}

static int handle_exit_prlimit64(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getrusage(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // who
    return 0;
}

static int handle_exit_getrusage(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_setpriority(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // which
    event.arg1 = std::to_string(e->arg_u32[0]); // who
    event.arg2 = std::to_string(e->arg_s32[1]); // priority
    add_event(event);
    return 0;
}

static int handle_exit_setpriority(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_getpriority(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // which
    event.arg1 = std::to_string(e->arg_u32[0]); // who
    add_event(event);
    return 0;
}

static int handle_exit_getpriority(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_ioprio_set(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // which
    event.arg1 = std::to_string(e->arg_s32[1]); // who
    event.arg2 = std::to_string(e->arg_s32[2]); // ioprio
    add_event(event);
    return 0;
}

static int handle_exit_ioprio_set(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_ioprio_get(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // which
    event.arg1 = std::to_string(e->arg_s32[1]); // who
    add_event(event);
    return 0;
}

static int handle_exit_ioprio_get(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mmap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // length
    event.arg2 = std::to_string(e->arg_s32[0]); // prot
    event.arg3 = std::to_string(e->arg_s32[1]); // flags
    event.arg4 = std::to_string(e->arg_s32[2]); // fd
    event.arg5 = std::to_string(e->arg_u64[2]); // offset
    add_event(event);
    return 0;
}

static int handle_exit_mmap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mprotect(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    event.arg1 = std::to_string(e->arg_s32[0]); // prot
    add_event(event);
    return 0;
}

static int handle_exit_mprotect(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_capset(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // header_version
    event.arg1 = std::to_string(e->arg_u32[1]); // header_pid
    event.arg2 = std::to_string(e->arg_u32[2]); // data_effective
    event.arg3 = std::to_string(e->arg_u32[3]); // data_permitted
    event.arg4 = std::to_string(e->arg_u32[4]); // data_inheritable
    add_event(event);
    return 0;
}

static int handle_exit_capset(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_ptrace(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // request
    event.arg1 = std::to_string(e->arg_u32[0]); // pid
    add_event(event);
    return 0;
}

static int handle_exit_ptrace(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_process_vm_readv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_u64[0]); // local_iov_len
    event.arg2 = std::to_string(e->arg_u64[1]); // remote_iov_len
    event.arg3 = std::to_string(e->arg_u64[2]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_process_vm_readv(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_process_vm_writev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_u64[0]); // local_iov_len
    event.arg2 = std::to_string(e->arg_u64[1]); // remote_iov_len
    event.arg3 = std::to_string(e->arg_u64[2]); // flags
    return 0;
}

static int handle_exit_process_vm_writev(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_init_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // param
    }
    add_event(event);
    return 0;
}

static int handle_exit_init_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_finit_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid)
    {
        event.arg1 = std::string(reinterpret_cast<const char *>(e->arg_str)); // param
    }
    add_event(event);
    return 0;
}

static int handle_exit_finit_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_delete_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::string(reinterpret_cast<const char *>(e->arg_str)); // name
    event.arg1 = std::to_string(e->arg_s32[0]);                           // flags
    add_event(event);
    return 0;
}

static int handle_exit_delete_module(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_munmap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // len
    return 0;
}

static int handle_exit_munmap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mremap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // old_addr
    event.arg1 = std::to_string(e->arg_u64[1]); // old_len
    event.arg2 = std::to_string(e->arg_u64[2]); // new_len
    event.arg3 = std::to_string(e->arg_s32[0]); // flags
    event.arg4 = std::to_string(e->arg_u64[3]); // new_addr
    add_event(event);
    return 0;
}

static int handle_exit_mremap(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_madvise(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // len
    event.arg2 = std::to_string(e->arg_s32[0]); // advice
    add_event(event);
    return 0;
}

static int handle_exit_madvise(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mlock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // len
    add_event(event);
    return 0;
}

static int handle_exit_mlock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mlock2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // len
    event.arg2 = std::to_string(e->arg_s32[0]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_mlock2(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_munlock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    event.arg1 = std::to_string(e->arg_u64[1]); // len
    add_event(event);
    return 0;
}

static int handle_exit_munlock(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_mlockall(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // flags
    add_event(event);
    return 0;
}

static int handle_exit_mlockall(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_munlockall(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_munlockall(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

// static int handle_enter_mincore(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.arg0 = std::to_string(e->arg_u64[0]); // addr
//     event.arg1 = std::to_string(e->arg_u64[1]); // len
//     add_event(event);
//     return 0;
// }

// static int handle_exit_mincore(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.ret = e->ret;
//     add_event(event);
//     return 0;
// }

// static int handle_enter_membarrier(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.arg0 = std::to_string(e->arg_s32[0]); // cmd
//     event.arg1 = std::to_string(e->arg_u32[0]); // flags
//     event.arg2 = std::to_string(e->arg_s32[1]); // cpu_id
//     add_event(event);
//     return 0;
// }

// static int handle_exit_membarrier(const struct event_t *e, const db_event_t& base_event) {
//     db_event_t event = base_event;

//     event.ret = e->ret;
//     add_event(event);
//     return 0;
// }

static int handle_enter_capget(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_capget(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid)
    {
        event.arg0 = std::to_string(e->arg_u32[0]); // header_version
        event.arg1 = std::to_string(e->arg_u32[1]); // header_pid
        event.arg2 = std::to_string(e->arg_u32[2]); // data_effective
        event.arg3 = std::to_string(e->arg_u32[3]); // data_permitted
        event.arg4 = std::to_string(e->arg_u32[4]); // data_inheritable
    }
    add_event(event);
    return 0;
}

static int handle_enter_prctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // option
    add_event(event);
    return 0;
}

static int handle_exit_prctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_arch_prctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // option
    event.arg1 = std::to_string(e->arg_u64[0]); // addr
    add_event(event);
    return 0;
}

static int handle_exit_arch_prctl(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_kill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_s32[0]); // sig
    add_event(event);
    return 0;
}

static int handle_exit_kill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_tkill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // tid
    event.arg1 = std::to_string(e->arg_s32[0]); // sig
    add_event(event);
    return 0;
}

static int handle_exit_tkill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_tgkill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // tgid
    event.arg1 = std::to_string(e->arg_u32[1]); // tid
    event.arg2 = std::to_string(e->arg_s32[0]); // sig
    add_event(event);
    return 0;
}

static int handle_exit_tgkill(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_brk(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // addr
    add_event(event);
    return 0;
}

static int handle_exit_brk(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sched_setscheduler(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_s32[0]); // policy
    add_event(event);
    return 0;
}

static int handle_exit_sched_setscheduler(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sched_setaffinity(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // pid
    event.arg1 = std::to_string(e->arg_u64[0]); // cpusetsize
    add_event(event);
    return 0;
}

static int handle_exit_sched_setaffinity(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static int handle_enter_sysinfo(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    add_event(event);
    return 0;
}

static int handle_exit_sysinfo(const struct event_t *e, const db_event_t &base_event)
{
    db_event_t event = base_event;

    event.ret = e->ret;
    add_event(event);
    return 0;
}

static struct socket_handlers event_handler[MAX_EVENT_ID] = {0};

void init_event_handlers(void)
{
    event_handler[__NR_socket].enter = handle_enter_socket;
    event_handler[__NR_socket].exit = handle_exit_socket;
    event_handler[__NR_socketpair].enter = handle_enter_socketpair;
    event_handler[__NR_socketpair].exit = handle_exit_socketpair;
    event_handler[__NR_setsockopt].enter = handle_enter_setsockopt;
    event_handler[__NR_setsockopt].exit = handle_exit_setsockopt;
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
    event_handler[__NR_getsockopt].enter = handle_enter_getsockopt;
    event_handler[__NR_getsockopt].exit = handle_exit_getsockopt;
    event_handler[__NR_getsockname].enter = handle_enter_getsockname;
    event_handler[__NR_getsockname].exit = handle_exit_getsockname;
    event_handler[__NR_getpeername].enter = handle_enter_getpeername;
    event_handler[__NR_getpeername].exit = handle_exit_getpeername;
    event_handler[__NR_ioctl].enter = handle_enter_ioctl;
    event_handler[__NR_ioctl].exit = handle_exit_ioctl;
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
    // event_handler[__NR_name_to_handle_at].enter = handle_enter_name_to_handle_at;
    // event_handler[__NR_name_to_handle_at].exit = handle_exit_name_to_handle_at;
    // event_handler[__NR_open_by_handle_at].enter = handle_enter_open_by_handle_at;
    // event_handler[__NR_open_by_handle_at].exit = handle_exit_open_by_handle_at;
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
    event_handler[__NR_access].enter = handle_enter_access;
    event_handler[__NR_access].exit = handle_exit_access;
    event_handler[__NR_faccessat].enter = handle_enter_faccessat;
    event_handler[__NR_faccessat].exit = handle_exit_faccessat;
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
    event_handler[__NR_clone].enter = handle_enter_clone;
    event_handler[__NR_clone].exit = handle_exit_clone;
    event_handler[__NR_clone3].enter = handle_enter_clone3;
    event_handler[__NR_clone3].exit = handle_exit_clone3;
    event_handler[__NR_fork].enter = handle_enter_fork;
    event_handler[__NR_fork].exit = handle_exit_fork;
    event_handler[__NR_vfork].enter = handle_enter_vfork;
    event_handler[__NR_vfork].exit = handle_exit_vfork;
    event_handler[__NR_execve].enter = handle_enter_execve;
    event_handler[__NR_execve].exit = handle_exit_execve;
    event_handler[__NR_execveat].enter = handle_enter_execveat;
    event_handler[__NR_execveat].exit = handle_exit_execveat;
    event_handler[__NR_exit].enter = handle_enter_exit;
    event_handler[__NR_exit].exit = handle_exit_exit;
    event_handler[__NR_exit_group].enter = handle_enter_exit_group;
    event_handler[__NR_exit_group].exit = handle_exit_exit_group;
    event_handler[__NR_wait4].enter = handle_enter_wait4;
    event_handler[__NR_wait4].exit = handle_exit_wait4;
    event_handler[__NR_waitid].enter = handle_enter_waitid;
    event_handler[__NR_waitid].exit = handle_exit_waitid;
    event_handler[__NR_getpid].enter = handle_enter_getpid;
    event_handler[__NR_getpid].exit = handle_exit_getpid;
    event_handler[__NR_getppid].enter = handle_enter_getppid;
    event_handler[__NR_getppid].exit = handle_exit_getppid;
    event_handler[__NR_gettid].enter = handle_enter_gettid;
    event_handler[__NR_gettid].exit = handle_exit_gettid;
    event_handler[__NR_setsid].enter = handle_enter_setsid;
    event_handler[__NR_setsid].exit = handle_exit_setsid;
    event_handler[__NR_getsid].enter = handle_enter_getsid;
    event_handler[__NR_getsid].exit = handle_exit_getsid;
    event_handler[__NR_setpgid].enter = handle_enter_setpgid;
    event_handler[__NR_setpgid].exit = handle_exit_setpgid;
    event_handler[__NR_getpgid].enter = handle_enter_getpgid;
    event_handler[__NR_getpgid].exit = handle_exit_getpgid;
    event_handler[__NR_getpgrp].enter = handle_enter_getpgrp;
    event_handler[__NR_getpgrp].exit = handle_exit_getpgrp;
    event_handler[__NR_setuid].enter = handle_enter_setuid;
    event_handler[__NR_setuid].exit = handle_exit_setuid;
    event_handler[__NR_getuid].enter = handle_enter_getuid;
    event_handler[__NR_getuid].exit = handle_exit_getuid;
    event_handler[__NR_setgid].enter = handle_enter_setgid;
    event_handler[__NR_setgid].exit = handle_exit_setgid;
    event_handler[__NR_getgid].enter = handle_enter_getgid;
    event_handler[__NR_getgid].exit = handle_exit_getgid;
    event_handler[__NR_setresuid].enter = handle_enter_setresuid;
    event_handler[__NR_setresuid].exit = handle_exit_setresuid;
    event_handler[__NR_getresuid].enter = handle_enter_getresuid;
    event_handler[__NR_getresuid].exit = handle_exit_getresuid;
    event_handler[__NR_setresgid].enter = handle_enter_setresgid;
    event_handler[__NR_setresgid].exit = handle_exit_setresgid;
    event_handler[__NR_getresgid].enter = handle_enter_getresgid;
    event_handler[__NR_getresgid].exit = handle_exit_getresgid;
    event_handler[__NR_setreuid].enter = handle_enter_setreuid;
    event_handler[__NR_setreuid].exit = handle_exit_setreuid;
    event_handler[__NR_setregid].enter = handle_enter_setregid;
    event_handler[__NR_setregid].exit = handle_exit_setregid;
    event_handler[__NR_geteuid].enter = handle_enter_geteuid;
    event_handler[__NR_geteuid].exit = handle_exit_geteuid;
    event_handler[__NR_getegid].enter = handle_enter_getegid;
    event_handler[__NR_getegid].exit = handle_exit_getegid;
    event_handler[__NR_setgroups].enter = handle_enter_setgroups;
    event_handler[__NR_setgroups].exit = handle_exit_setgroups;
    event_handler[__NR_getgroups].enter = handle_enter_getgroups;
    event_handler[__NR_getgroups].exit = handle_exit_getgroups;
    event_handler[__NR_setns].enter = handle_enter_setns;
    event_handler[__NR_setns].exit = handle_exit_setns;
    event_handler[__NR_setrlimit].enter = handle_enter_setrlimit;
    event_handler[__NR_setrlimit].exit = handle_exit_setrlimit;
    event_handler[__NR_getrlimit].enter = handle_enter_getrlimit;
    event_handler[__NR_getrlimit].exit = handle_exit_getrlimit;
    event_handler[__NR_prlimit64].enter = handle_enter_prlimit64;
    event_handler[__NR_prlimit64].exit = handle_exit_prlimit64;
    event_handler[__NR_getrusage].enter = handle_enter_getrusage;
    event_handler[__NR_getrusage].exit = handle_exit_getrusage;
    event_handler[__NR_setpriority].enter = handle_enter_setpriority;
    event_handler[__NR_setpriority].exit = handle_exit_setpriority;
    event_handler[__NR_getpriority].enter = handle_enter_getpriority;
    event_handler[__NR_getpriority].exit = handle_exit_getpriority;
    event_handler[__NR_ioprio_set].enter = handle_enter_ioprio_set;
    event_handler[__NR_ioprio_set].exit = handle_exit_ioprio_set;
    event_handler[__NR_ioprio_get].enter = handle_enter_ioprio_get;
    event_handler[__NR_ioprio_get].exit = handle_exit_ioprio_get;
    event_handler[__NR_mmap].enter = handle_enter_mmap;
    event_handler[__NR_mmap].exit = handle_exit_mmap;
    event_handler[__NR_mprotect].enter = handle_enter_mprotect;
    event_handler[__NR_mprotect].exit = handle_exit_mprotect;
    event_handler[__NR_capset].enter = handle_enter_capset;
    event_handler[__NR_capset].exit = handle_exit_capset;
    event_handler[__NR_ptrace].enter = handle_enter_ptrace;
    event_handler[__NR_ptrace].exit = handle_exit_ptrace;
    event_handler[__NR_process_vm_readv].enter = handle_enter_process_vm_readv;
    event_handler[__NR_process_vm_readv].exit = handle_exit_process_vm_readv;
    event_handler[__NR_process_vm_writev].enter = handle_enter_process_vm_writev;
    event_handler[__NR_process_vm_writev].exit = handle_exit_process_vm_writev;
    event_handler[__NR_init_module].enter = handle_enter_init_module;
    event_handler[__NR_init_module].exit = handle_exit_init_module;
    event_handler[__NR_finit_module].enter = handle_enter_finit_module;
    event_handler[__NR_finit_module].exit = handle_exit_finit_module;
    event_handler[__NR_delete_module].enter = handle_enter_delete_module;
    event_handler[__NR_delete_module].exit = handle_exit_delete_module;
    event_handler[__NR_munmap].enter = handle_enter_munmap;
    event_handler[__NR_munmap].exit = handle_exit_munmap;
    event_handler[__NR_mremap].enter = handle_enter_mremap;
    event_handler[__NR_mremap].exit = handle_exit_mremap;
    event_handler[__NR_madvise].enter = handle_enter_madvise;
    event_handler[__NR_madvise].exit = handle_exit_madvise;
    event_handler[__NR_mlock].enter = handle_enter_mlock;
    event_handler[__NR_mlock].exit = handle_exit_mlock;
    event_handler[__NR_mlock2].enter = handle_enter_mlock2;
    event_handler[__NR_mlock2].exit = handle_exit_mlock2;
    event_handler[__NR_munlock].enter = handle_enter_munlock;
    event_handler[__NR_munlock].exit = handle_exit_munlock;
    event_handler[__NR_mlockall].enter = handle_enter_mlockall;
    event_handler[__NR_mlockall].exit = handle_exit_mlockall;
    event_handler[__NR_munlockall].enter = handle_enter_munlockall;
    event_handler[__NR_munlockall].exit = handle_exit_munlockall;
    // event_handler[__NR_mincore].enter = handle_enter_mincore;
    // event_handler[__NR_mincore].exit = handle_exit_mincore;
    // event_handler[__NR_membarrier].enter = handle_enter_membarrier;
    // event_handler[__NR_membarrier].exit = handle_exit_membarrier;
    event_handler[__NR_capget].enter = handle_enter_capget;
    event_handler[__NR_capget].exit = handle_exit_capget;
    event_handler[__NR_prctl].enter = handle_enter_prctl;
    event_handler[__NR_prctl].exit = handle_exit_prctl;
    event_handler[__NR_arch_prctl].enter = handle_enter_arch_prctl;
    event_handler[__NR_arch_prctl].exit = handle_exit_arch_prctl;
    event_handler[__NR_kill].enter = handle_enter_kill;
    event_handler[__NR_kill].exit = handle_exit_kill;
    event_handler[__NR_tkill].enter = handle_enter_tkill;
    event_handler[__NR_tkill].exit = handle_exit_tkill;
    event_handler[__NR_tgkill].enter = handle_enter_tgkill;
    event_handler[__NR_tgkill].exit = handle_exit_tgkill;
    event_handler[__NR_brk].enter = handle_enter_brk;
    event_handler[__NR_brk].exit = handle_exit_brk;
    event_handler[__NR_sched_setscheduler].enter = handle_enter_sched_setscheduler;
    event_handler[__NR_sched_setscheduler].exit = handle_exit_sched_setscheduler;
    event_handler[__NR_sched_setaffinity].enter = handle_enter_sched_setaffinity;
    event_handler[__NR_sched_setaffinity].exit = handle_exit_sched_setaffinity;
    event_handler[__NR_sysinfo].enter = handle_enter_sysinfo;
    event_handler[__NR_sysinfo].exit = handle_exit_sysinfo;
}

// debug
long long count = 0;

int handle_event(void *ctx, void *data, size_t data_sz)
{
    static auto start_time = std::chrono::steady_clock::now(); // 시작 시간 저장
    count++;
    if (count % 100000 == 0)
    {
        auto current_time = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = current_time - start_time;
        double events_per_second = count / elapsed_seconds.count();
        printf("[+]Event count: %lld, Events per second: %.2f\n", count, events_per_second);
    }
    const struct event_t *e = (struct event_t *)data;

    db_event_t base_event = get_str(&e->task, boot_time);

    struct socket_handlers *handlers = &event_handler[e->task.event_id];
    event_handler_t handler = e->is_enter ? handlers->enter : handlers->exit;
    if (handler)
    {
        base_event.is_enter = e->is_enter;
        return handler(e, base_event);
    }
    return 0;
}