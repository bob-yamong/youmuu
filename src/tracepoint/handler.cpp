#include "handler.h"

#define NANOSECONDS_IN_A_SECOND 1000000000
#define MAX_EVENT_ID 1024

time_t boot_time;
EventBuffer event_buffer;

static db_event_t get_str(const struct current_task *task, time_t boot_time) {
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
    // Safely get the container_id from the map
    auto it = pid_namespace_to_container_id.find(task->pid_namespace);
    if (it != pid_namespace_to_container_id.end()) {
        event.container_name = it->second;
    } else {
        event.container_name = "Unknown"; // or handle as appropriate
    }
    event.ppid = task->ppid;
    event.pid = task->pid;
    event.tid = task->tid;
    event.uid = task->uid;
    event.gid = task->gid;
    event.comm = std::string(reinterpret_cast<const char*>(task->comm));

    return event;
}

typedef int (*event_handler_t)(const struct event_t *e, const db_event_t& base_event);

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

static int handle_enter_socket(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // domain
    event.arg1 = std::to_string(e->arg_s32[1]); // type
    event.arg2 = std::to_string(e->arg_s32[2]); // protocol
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_socket(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_socketpair(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // domain
    event.arg1 = std::to_string(e->arg_s32[1]); // type
    event.arg2 = std::to_string(e->arg_s32[2]); // protocol
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_socketpair(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid) {
        event.arg0 = std::to_string(e->arg_s32[0]); // sv[0]
        event.arg1 = std::to_string(e->arg_s32[1]); // sv[1]
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_setsockopt(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // level
    event.arg2 = std::to_string(e->arg_s32[2]); // optname
    event.arg4 = std::to_string(e->arg_s32[3]); // optlen
    if (e->is_valid) {
        event.arg3 = std::to_string(e->arg_u32[0]); // optval
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_setsockopt(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_getsockopt(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // level
    event.arg2 = std::to_string(e->arg_s32[2]); // optname
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_getsockopt(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid) {
        event.arg0 = std::to_string(e->arg_u32[0]); // optval
        event.arg1 = std::to_string(e->arg_u32[1]); // optlen
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_getsockname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_getsockname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_getpeername(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_getpeername(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_bind(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_bind(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_listen(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // backlog
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_listen(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_accept(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_accept(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null) {
        event.additional_info = "socket address info is not requested";
    }
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_accept4(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // flags
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_accept4(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null) {
        event.additional_info = "socket address info is not requested";
    }
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_connect(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_connect(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_shutdown(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // how
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_shutdown(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_recvfrom (const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // msg_len
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_recvfrom(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_null) {
        event.additional_info = "socket address info is not requested";
    }
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = ip_str;    // ip
        event.arg1 = std::to_string(e->port);   // port
        event.arg2 = std::to_string(e->addr_family);    // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_recvmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // msg_len
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    event_buffer.add_event(base_event);
    return 0;
}

static int handle_exit_recvmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg0 = std::string(ip_str); // src_addr
        event.arg1 = std::to_string(e->port); // src_port
        event.arg2 = std::to_string(e->addr_family); // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_recvmmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // vlen
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_recvmmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_sendto(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // msg_len
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg3 = std::string(ip_str); // dest_addr
        event.arg4 = std::to_string(e->port); // dest_port
        event.arg5 = std::to_string(e->addr_family); // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_sendto(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_sendmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid) {
        char ip_str[INET6_ADDRSTRLEN];
        get_ip_str(e, ip_str, sizeof(ip_str));
        event.arg2 = std::string(ip_str); // dest_addr
        event.arg3 = std::to_string(e->port); // dest_port
        event.arg4 = std::to_string(e->addr_family); // ip_version
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_sendmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_sendmmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // socketfd
    event.arg1 = std::to_string(e->arg_u64[0]); // vlen
    event.arg2 = std::to_string(e->arg_s32[1]); // flags
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_sendmmsg(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_sethostname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str));    // hostname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_sethostname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_setdomainname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u64[0]); // len
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str));    // domainname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_setdomainname(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_ioctl(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // op
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_ioctl(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_close(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_close(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_creat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid) {
        event.arg0 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_creat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_open(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_s32[0]); // flags
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    if (e->is_valid) {
        event.arg0 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_open(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_openat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[1]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // flags
    event.arg3 = std::to_string(e->arg_u32[1]); // mode
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_openat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_openat2(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg5 = std::to_string(e->arg_u64[0]); // size
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
        event.arg2 = std::to_string(e->arg_u64[1]); // flags
        event.arg3 = std::to_string(e->arg_u64[2]); // mode
        event.arg4 = std::to_string(e->arg_u64[3]); // resolve
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_openat2(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_name_to_handle_at(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg5 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
        event.arg2 = std::to_string(e->arg_u32[0]); // hadle_bytes
        event.arg3 = std::to_string(e->arg_s32[3]); // handle_type
        event.arg4 = std::to_string(e->arg_s32[2]); // mount_id
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_name_to_handle_at(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_open_by_handle_at(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // mount_fd
    event.arg3 = std::to_string(e->arg_s32[1]); // flags
    if (e->is_valid) {
        event.arg1 = std::to_string(e->arg_u32[0]); // handle_bytes
        event.arg2 = std::to_string(e->arg_s32[2]); // handle_type
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_open_by_handle_at(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_memfd_create(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_u32[0]); // flags
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // name
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_memfd_create(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_mknod(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u32[0]); // mode
    event.arg2 = std::to_string(e->arg_u64[0]); // dev
    if (e->is_valid) {
        event.arg0 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_mknod(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_mknodat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // dirfd
    event.arg2 = std::to_string(e->arg_u32[0]); // mode
    event.arg3 = std::to_string(e->arg_u64[0]); // dev
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_mknodat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_rename(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    if (e->is_valid) {
        event.arg0 = std::string(reinterpret_cast<const char*>(e->arg_str)); // oldpath
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str2)); // newpath
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_rename(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_renameat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // olddirfd
    event.arg2 = std::to_string(e->arg_s32[1]); // newdirfd
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // oldpath
        event.arg3 = std::string(reinterpret_cast<const char*>(e->arg_str2)); // newpath
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_renameat(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_renameat2(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[1]); // olddirfd
    event.arg2 = std::to_string(e->arg_s32[2]); // newdirfd
    event.arg4 = std::to_string(e->arg_u64[0]); // flags
    if (e->is_valid) {
        event.arg1 = std::string(reinterpret_cast<const char*>(e->arg_str)); // oldpath
        event.arg3 = std::string(reinterpret_cast<const char*>(e->arg_str2)); // newpath
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_renameat2(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_truncate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg1 = std::to_string(e->arg_u64[0]); // length
    if (e->is_valid) {
        event.arg0 = std::string(reinterpret_cast<const char*>(e->arg_str)); // pathname
    }
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_truncate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_ftruncate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_u64[0]); // length
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_ftruncate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

static int handle_enter_fallocate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.arg0 = std::to_string(e->arg_s32[0]); // fd
    event.arg1 = std::to_string(e->arg_s32[1]); // mode
    event.arg2 = std::to_string(e->arg_u64[0]); // offset
    event.arg3 = std::to_string(e->arg_u64[1]); // len
    event_buffer.add_event(event);
    return 0;
}

static int handle_exit_fallocate(const struct event_t *e, const db_event_t& base_event) {
    db_event_t event = base_event;

    event.ret = e->ret;
    event_buffer.add_event(event);
    return 0;
}

// static int handle_enter_mkdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter mkdir: %s, pathname=%s, mode=%#x\n",
//                 e->arg_str, e->arg_u32[0]);
//     } else {
//         printf("Enter mkdir: %s, failed to read pathname, mode=%#x\n",
//                 e->arg_u32[0]);
//     }
//     return 0;
// }

// static int handle_exit_mkdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mkdir: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mkdir: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mkdirat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter mkdirat: %s, dirfd=%d, pathname=%s, mode=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_u32[0]);
//     } else {
//         printf("Enter mkdirat: %s, dirfd=%d, failed to read pathname, mode=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0]);
//     }
//     return 0;
// }

// static int handle_exit_mkdirat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mkdirat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mkdirat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_rmdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter rmdir: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter rmdir: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_rmdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit rmdir: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit rmdir: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getcwd(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getcwd: %s, size=%llu\n",
//             e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_getcwd(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getcwd: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getcwd: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_chdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter chdir: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter chdir: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_chdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit chdir: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit chdir: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fchdir(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fchdir: %s, fd=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_fchdir(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fchdir: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fchdir: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_chroot(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter chroot: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter chroot: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_chroot(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit chroot: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit chroot: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_pivot_root(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter pivot_root: %s, new_root=%s, put_old=%s\n",
//                 e->arg_str, e->arg_str2);
//     } else {
//         printf("Enter pivot_root: %s, failed to read new_root, put_old\n",
                
//     }
//     return 0;
// }

// static int handle_exit_pivot_root(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit pivot_root: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit pivot_root: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getdents(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getdents: %s, fd=%u, count=%u\n",
//             e->arg_u32[0], e->arg_u32[1]);
//     return 0;
// }

// static int handle_exit_getdents(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getdents: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Exit getdents: success, %s, data=%llu, ret=%lld, \n",
//                 e->arg_u64[0], e->ret);
//     } else {
//         printf("Exit getdents: success, %s, failed to read data, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getdents64(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getdents64: %s, fd=%d, count=%llu\n",
//             e->arg_s32[0], e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_getdents64(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getdents64: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Exit getdents64: success, %s, data=%llu, ret=%lld, \n",
//                 e->arg_u64[0], e->ret);
//     } else {
//         printf("Exit getdents64: success, %s, failed to read data, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_link(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter link: %s, oldpath=%s, newpath=%s\n",
//                 e->arg_str, e->arg_str2);
//     } else {
//         printf("Enter link: %s, failed to read oldpath, newpath\n",
                
//     }
//     return 0;
// }

// static int handle_exit_link(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit link: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit link: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_linkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter linkat: %s, olddirfd=%d, oldpath=%s, newdirfd=%d, newpath=%s, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2, e->arg_s32[2]);
//     } else {
//         printf("Enter linkat: %s, olddirfd=%d, newdirfd=%d, failed to read oldpath, newpath, flags=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//     }
//     return 0;
// }

// static int handle_exit_linkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit linkat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit linkat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_symlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter symlink: %s, target=%s, linkpath=%s\n",
//                 e->arg_str, e->arg_str2);
//     } else {
//         printf("Enter symlink: %s, failed to read target, linkpath\n",
                
//     }
//     return 0;
// }

// static int handle_exit_symlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit symlink: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit symlink: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_symlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter symlinkat: %s, target=%s, newdirfd=%d, linkpath=%s\n",
//                 e->arg_str, e->arg_s32[0], e->arg_str2);
//     } else {
//         printf("Enter symlinkat: %s, newdirfd=%d, failed to read target, linkpath\n",
//                 e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_symlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit symlinkat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit symlinkat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_unlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter unlink: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter unlink: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_unlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit unlink: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit unlink: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_unlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter unlinkat: %s, dirfd=%d, pathname=%s, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1]);
//     } else {
//         printf("Enter unlinkat: %s, dirfd=%d, failed to read pathname, flags=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_unlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit unlinkat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit unlinkat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_readlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter readlink: %s, pathname=%s, size=%llu\n",
//                 e->arg_str, e->arg_u64[0]);
//     } else {
//         printf("Enter readlink: %s, failed to read pathname, size=%llu\n",
//                 e->arg_u64[0]);
//     }
//     return 0;
// }

// static int handle_exit_readlink(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit readlink: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit readlink: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_readlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter readlinkat: %s, dirfd=%d, pathname=%s, size=%llu\n",
//                 e->arg_s32[0], e->arg_str, e->arg_u64[0]);
//     } else {
//         printf("Enter readlinkat: %s, dirfd=%d, failed to read pathname, size=%llu\n",
//                 e->arg_s32[0], e->arg_u64[0]);
//     }
//     return 0;
// }

// static int handle_exit_readlinkat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit readlinkat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit readlinkat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_umask(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter umask: %s, mask=%#x\n",
//             e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_umask(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit umask: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit umask: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_newstat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter newstat: %s, filename=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter newstat: %s, failed to read filename\n",
                
//     }
//     return 0;
// }

// static int handle_exit_newstat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit newstat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit newstat: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_newlstat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter newlstat: %s, filename=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter newlstat: %s, failed to read filename\n",
                
//     }
//     return 0;
// }

// static int handle_exit_newlstat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit newlstat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit newlstat: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_newfstat(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter newfstat: %s, fd=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_newfstat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit newfstat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit newfstat: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_newfstatat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter newfstatat: %s, dirfd=%d, pathname=%s, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1]);
//     } else {
//         printf("Enter newfstatat: %s, dirfd=%d, failed to read pathname, flags=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_newfstatat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit newfstatat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit newfstatat: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_statx(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter statx: %s, dirfd=%d, pathname=%s, flags=%#x, mask=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_u32[0]);
//     } else {
//         printf("Enter statx: %s, dirfd=%d, failed to read pathname, flags=%#x, mask=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1], e->arg_u32[0]);
//     }
//     return 0;
// }

// static int handle_exit_statx(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit statx: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit statx: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_statfs(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter statfs: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter statfs: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_statfs(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit statfs: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit statfs: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fstatfs(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fstatfs: %s, fd=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_fstatfs(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fstatfs: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fstatfs: success, %s, ret=%lld, \n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_chmod(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter chmod: %s, pathname=%s, mode=%#x\n",
//                 e->arg_str, e->arg_u32[0]);
//     } else {
//         printf("Enter chmod: %s, failed to read pathname, mode=%#x\n",
//                 e->arg_u32[0]);
//     }
//     return 0;
// }

// static int handle_exit_chmod(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit chmod: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit chmod: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fchmod(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fchmod: %s, fd=%d, mode=%#x\n",
//             e->arg_s32[0], e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_fchmod(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fchmod: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fchmod: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fchmodat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter fchmodat: %s, dirfd=%d, pathname=%s, mode=%#x, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_s32[1]);
//     } else {
//         printf("Enter fchmodat: %s, dirfd=%d, failed to read pathname, mode=%#x, flags=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_fchmodat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fchmodat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fchmodat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_chown(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter chown: %s, pathname=%s, owner=%u, group=%u\n",
//                 e->arg_str, e->arg_u32[0], e->arg_u32[1]);
//     } else {
//         printf("Enter chown: %s, failed to read pathname, owner=%u, group=%u\n",
//                 e->arg_u32[0], e->arg_u32[1]);
//     }
//     return 0;
// }

// static int handle_exit_chown(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit chown: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit chown: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_lchown(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter lchown: %s, pathname=%s, owner=%u, group=%u\n",
//                 e->arg_str, e->arg_u32[0], e->arg_u32[1]);
//     } else {
//         printf("Enter lchown: %s, failed to read pathname, owner=%u, group=%u\n",
//                 e->arg_u32[0], e->arg_u32[1]);
//     }
//     return 0;
// }

// static int handle_exit_lchown(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit lchown: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit lchown: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fchown(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fchown: %s, fd=%d, owner=%u, group=%u\n",
//             e->arg_s32[0], e->arg_u32[0], e->arg_u32[1]);
//     return 0;
// }

// static int handle_exit_fchown(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fchown: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fchown: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fchownat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter fchownat: %s, dirfd=%d, pathname=%s, owner=%u, group=%u, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_u32[0], e->arg_u32[1], e->arg_s32[1]);
//     } else {
//         printf("Enter fchownat: %s, dirfd=%d, failed to read pathname, owner=%u, group=%u, flags=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0], e->arg_u32[1], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_fchownat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fchownat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fchownat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_access(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter access: %s, pathname=%s, mode=%#x\n",
//                 e->arg_str, e->arg_s32[0]);
//     } else {
//         printf("Enter access: %s, failed to read pathname, mode=%#x\n",
//                 e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_access(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit access: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit access: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_faccessat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter faccessat: %s, dirfd=%d, pathname=%s, mode=%#x, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_s32[2]);
//     } else {
//         printf("Enter faccessat: %s, dirfd=%d, failed to read pathname, mode=%#x, flags=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//     }
//     return 0;
// }

// static int handle_exit_faccessat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit faccessat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit faccessat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fcntl(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fcntl: %s, fd=%d, cmd=%#llx, arg=%llu\n",
//             e->arg_s32[0], e->arg_u64[0], e->arg_u64[1]);
//     return 0;
// }

// static int handle_exit_fcntl(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fcntl: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fcntl: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_dup(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter dup: %s, oldfd=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_dup(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit dup: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit dup: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_dup2(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter dup2: %s, oldfd=%d, newfd=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_dup2(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit dup2: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit dup2: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_dup3(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter dup3: %s, oldfd=%d, newfd=%d, flags=%#x\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//     return 0;
// }

// static int handle_exit_dup3(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit dup3: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit dup3: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_flock(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter flock: %s, fd=%d, operation=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_flock(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit flock: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit flock: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_read(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter read: %s, fd=%d, count=%llu\n",
//             e->arg_s32[0], e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_read(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit read: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit read: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_pread64(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter pread: %s, fd=%d, count=%llu, offset=%lld\n",
//             e->arg_s32[0], e->arg_u64[0], e->arg_s64[0]);
//     return 0;
// }

// static int handle_exit_pread64(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit pread: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit pread: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_readv(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter readv: %s, fd=%d, iov_count=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_readv(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit readv: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit readv: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_preadv(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter preadv: %s, fd=%d, iov_count=%d, offset=%lld\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s64[0]);
//     return 0;
// }

// static int handle_exit_preadv(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit preadv: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit preadv: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_preadv2(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter preadv2: %s, fd=%d, iov_count=%d, offset=%lld, flags=%#x\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_s32[2]);
//     return 0;
// }

// static int handle_exit_preadv2(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit preadv2: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit preadv2: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_write(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter write: %s, fd=%d, count=%llu\n",
//             e->arg_s32[0], e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_write(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit write: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit write: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_pwrite64(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter pwrite: %s, fd=%d, count=%llu, offset=%lld\n",
//             e->arg_s32[0], e->arg_u64[0], e->arg_s64[0]);
//     return 0;
// }

// static int handle_exit_pwrite64(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit pwrite: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit pwrite: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_writev(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter writev: %s, fd=%d, iov_count=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_writev(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit writev: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit writev: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_pwritev(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter pwritev: %s, fd=%d, iov_count=%d, offset=%lld\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s64[0]);
//     return 0;
// }

// static int handle_exit_pwritev(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit pwritev: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit pwritev: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_pwritev2(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter pwritev2: %s, fd=%d, iov_count=%d, offset=%lld, flags=%#x\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_s32[2]);
//     return 0;
// }

// static int handle_exit_pwritev2(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit pwritev2: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit pwritev2: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_lseek(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter lseek: %s, fd=%d, offset=%lld, whence=%d\n",
//             e->arg_s32[0], e->arg_s64[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_lseek(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit lseek: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit lseek: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_sendfile64(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter sendfile64: %s, out_fd=%d, in_fd=%d, offset=%lld, count=%llu\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s64[0], e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_sendfile64(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit sendfile64: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit sendfile64: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_inotify_init(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter inotify_init: %s\n", 
//     return 0;
// }

// static int handle_exit_inotify_init(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit inotify_init: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit inotify_init: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_inotify_init1(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter inotify_init1: %s, flags=%#x\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_inotify_init1(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit inotify_init1: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit inotify_init1: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_inotify_add_watch(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter inotify_add_watch: %s, fd=%d, pathname=%s, mask=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_u32[0]);
//     } else {
//         printf("Enter inotify_add_watch: %s, fd=%d, failed to read pathname, mask=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0]);
//     }
//     return 0;
// }

// static int handle_exit_inotify_add_watch(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit inotify_add_watch: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit inotify_add_watch: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_inotify_rm_watch(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter inotify_rm_watch: %s, fd=%d, wd=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_inotify_rm_watch(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit inotify_rm_watch: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit inotify_rm_watch: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fanotify_init(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fanotify_init: %s, flags=%#x, event_f_flags=%#x\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_fanotify_init(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fanotify_init: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fanotify_init: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fanotify_mark(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_null == false) {
//         if (e->is_valid) {
//             printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%#x, mask=%#llx, dirfd=%d, pathname=%s\n",
//                     e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1], e->arg_str);
//         } else {
//             printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%#x, mask=%#llx, dirfd=%d, failed to read pathname\n",
//                     e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1]);
//         }
//     } else {
//         printf("Enter fanotify_mark: %s, fanotify_fd=%d, flags=%#x, mask=%#llx, dirfd=%d, pathname is NULL (monitoring directory events)\n",
//                 e->arg_s32[0], e->arg_u32[0], e->arg_u64[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_fanotify_mark(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fanotify_mark: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fanotify_mark: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter mount: %s, source=%s, target=%s, filesystemtype=%s, mountflags=%#llx\n",
//                 e->arg_str, e->arg_str2, e->filesystem_type, e->arg_u64[0]);
//     } else {
//         printf("Enter mount: %s, failed to read source, target, filesystemtype, mountflags=%#llx\n",
//                 e->arg_u64[0]);
//     }
//     return 0;
// }

// static int handle_exit_mount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mount: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mount: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_umount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter umount: %s, target=%s, flags=%#x\n",
//                 e->arg_str, e->arg_s32[0]);
//     } else {
//         printf("Enter umount: %s, failed to read target, flags=%#x\n",
//                 e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_umount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit umount: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit umount: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_move_mount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter move_mount: %s, from_fd=%d, from_pathname=%s, to_fd=%d, to_pathname=%s, flags=%#llx\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1], e->arg_str2, e->arg_u64[0]);
//     } else {
//         printf("Enter move_mount: %s, from_fd=%d, to_fd=%d, failed to read from_fd, from_pathname, to_fd, to_pathname, flags=%#llx\n",
//                 e->arg_s32[0], e->arg_s32[1], e->arg_u64[0]);
//     }
//     return 0;
// }

// static int handle_exit_move_mount(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit move_mount: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit move_mount: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_clone(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter clone: %s, fn_ptr=%llu, flags=%#x\n",
//             e->arg_u64[0], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_clone(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit clone: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit clone: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_clone3(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter clone3: %s, flags=%#llx, stack=%llu, stack_size=%llu, cgroup=%llu\n",
//                 e->arg_u64[0], e->arg_u64[1], e->arg_u64[2], e->arg_u64[3]);
//     } else {
//         printf("Enter clone3: %s, failed to read flags, stack, stack_size, cgroup\n",
                
//     }
//     return 0;
// }

// static int handle_exit_clone3(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit clone3: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit clone3: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_fork(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter fork: %s\n", 
//     return 0;
// }

// static int handle_exit_fork(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit fork: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit fork: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_vfork(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter vfork: %s\n", 
//     return 0;
// }

// static int handle_exit_vfork(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit vfork: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit vfork: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_execve(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter execve: %s, pathname=%s\n",
//                 e->arg_str);
//     } else {
//         printf("Enter execve: %s, failed to read pathname\n",
                
//     }
//     return 0;
// }

// static int handle_exit_execve(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit execve: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit execve: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_execveat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter execveat: %s, dirfd=%d, pathname=%s, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1]);
//     } else {
//         printf("Enter execveat: %s, dirfd=%d, failed to read pathname, flags=%#x\n",
//                 e->arg_s32[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_execveat(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit execveat: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit execveat: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_exit(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter exit: %s, status=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_exit(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit exit: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit exit: success, %s\n", 
                
//     }
//     return 0;
// }

// static int handle_enter_exit_group(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter exit_group: %s, status=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_exit_group(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit exit_group: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit exit_group: success, %s\n", 
                
//     }
//     return 0;
// }

// static int handle_enter_wait4(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter wait4: %s, pid=%u, status=%d, options=%#x\n",
//                 e->arg_u32[0], e->arg_s32[1], e->arg_s32[0]);
//     } else {
//         printf("Enter wait4: %s, pid=%u, failed to read status, options=%#x\n",
//                 e->arg_u32[0], e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_wait4(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit wait4: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit wait4: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_waitid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter waitid: %s, idtype=%d, pid=%u, si_signo=%d, si_code=%d, options=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0], e->arg_s32[2], e->arg_s32[3], e->arg_s32[1]);
//     } else {
//         printf("Enter waitid: %s, idtype=%d, pid=%u, failed to siginfo, options=%#x\n",
//                 e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//     }
//     return 0;
// }

// static int handle_exit_waitid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit waitid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit waitid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getpid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getpid: %s\n", 
//     return 0;
// }

// static int handle_exit_getpid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getpid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getpid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getppid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getppid: %s\n", 
//     return 0;
// }

// static int handle_exit_getppid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getppid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getppid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_gettid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter gettid: %s\n", 
//     return 0;
// }

// static int handle_exit_gettid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit gettid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit gettid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setsid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setsid: %s\n", 
//     return 0;
// }

// static int handle_exit_setsid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setsid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setsid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getsid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getsid: %s, pid=%u\n",
//             e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_getsid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getsid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getsid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setpgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setpgid: %s, pid=%u, pgid=%u\n",
//             e->arg_u32[0], e->arg_u32[1]);
//     return 0;
// }

// static int handle_exit_setpgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setpgid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setpgid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getpgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getpgid: %s, pid=%u\n",
//             e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_getpgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getpgid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getpgid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getpgrp(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getpgrp: %s\n", 
//     return 0;
// }

// static int handle_exit_getpgrp(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getpgrp: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getpgrp: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setreuid: %s, uid=%u\n",
//             e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_setuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setreuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setreuid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getuid: %s\n", 
//     return 0;
// }

// static int handle_exit_getuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getuid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setregid: %s, gid=%u\n",
//             e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_setgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setregid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setregid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getgid: %s\n", 
//     return 0;
// }

// static int handle_exit_getgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getgid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getgid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setresuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setresuid: %s, ruid=%u, euid=%u, suid=%u\n",
//             e->arg_u32[0], e->arg_u32[1], e->arg_u32[2]);
//     return 0;
// }

// static int handle_exit_setresuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setresuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setresuid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getresuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getresuid: %s\n", 
//     return 0;
// }

// static int handle_exit_getresuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getresuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Exit getresuid: success, %s, ruid=%u, euid=%u, suid=%u, ret=%lld\n",
//                 e->arg_u32[0], e->arg_u32[1], e->arg_u32[2], e->ret);
//     } else {
//         printf("Exit getresuid: success, %s, failed to read uid values, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setresgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setresgid: %s, rgid=%u, egid=%u, sgid=%u\n",
//             e->arg_u32[0], e->arg_u32[1], e->arg_u32[2]);
//     return 0;
// }

// static int handle_exit_setresgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setresgid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setresgid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getresgid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getresgid: %s\n", 
//     return 0;
// }

// static int handle_exit_getresgid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getresgid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Exit getresgid: success, %s, rgid=%u, egid=%u, sgid=%u, ret=%lld\n",
//                 e->arg_u32[0], e->arg_u32[1], e->arg_u32[2], e->ret);
//     } else {
//         printf("Exit getresgid: success, %s, failed to read gid values, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setreuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setreuid: %s, ruid=%u, euid=%u\n",
//             e->arg_u32[0], e->arg_u32[1]);
//     return 0;
// }

// static int handle_exit_setreuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setreuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setreuid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setregid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setregid: %s, rgid=%u, egid=%u\n",
//             e->arg_u32[0], e->arg_u32[1]);
//     return 0;
// }

// static int handle_exit_setregid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setregid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setregid: success, %s, ret=%lld\n", 
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_geteuid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter geteuid: %s\n", 
//     return 0;
// }

// static int handle_exit_geteuid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit geteuid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit geteuid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getegid(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getegid: %s\n", 
//     return 0;
// }

// static int handle_exit_getegid(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getegid: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getegid: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setgroups(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setgroups: %s, size=%llu\n",
//             e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_setgroups(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setgroups: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setgroups: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getgroups(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getgroups: %s, size=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_getgroups(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getgroups: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getgroups: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setns(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setns: %s, fd=%d, nstype=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_setns(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setns: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setns: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setrlimit(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter setrlimit: %s, resource=%d, rlim_cur=%llu, rlim_max=%llu\n",
//                 e->arg_s32[0], e->arg_u64[0], e->arg_u64[1]);
//     } else {
//         printf("Enter setrlimit: %s, resource=%d, failed to read rlim_cur, rlim_max\n",
//                 e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_setrlimit(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setrlimit: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setrlimit: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getrlimit(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getrlimit: %s, resource=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_getrlimit(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getrlimit: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Exit getrlimit: success, %s, rlim_cur=%llu, rlim_max=%llu, ret=%lld\n",
//                 e->arg_u64[0], e->arg_u64[1], e->ret);
//     } else {
//         printf("Exit getrlimit: success, %s, failed to read rlimit info, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_prlimit64(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter prlimit64: %s, pid=%u, resource=%d\n",
//             e->arg_u32[0], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_prlimit64(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit prlimit64: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit prlimit64: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getrusage(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getrusage: %s, who=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_getrusage(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getrusage: failed, %s, error_code=%lld\n",
//                 e->ret);
//     }else {
//         printf("Exit getrusage: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_setpriority(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter setpriority: %s, which=%d, who=%u, priority=%d\n",
//             e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_setpriority(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit setpriority: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit setpriority: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_getpriority(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter getpriority: %s, which=%d, who=%u\n",
//             e->arg_s32[0], e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_getpriority(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit getpriority: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit getpriority: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_ioprio_set(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter ioprio_set: %s, which=%d, who=%d, ioprio=%d\n",
//             e->arg_s32[0], e->arg_s32[1], e->arg_s32[2]);
//     return 0;
// }

// static int handle_exit_ioprio_set(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit ioprio_set: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit ioprio_set: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_ioprio_get(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter ioprio_get: %s, which=%d, who=%d\n",
//             e->arg_s32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_ioprio_get(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit ioprio_get: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit ioprio_get: success, %s, ioprio=%d, ret=%lld\n",
//                 e->arg_s32[2], e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mmap(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mmap: %s, addr=%#llx, length=%llu, prot=%#x, flags=%#x, fd=%d, offset=%llu\n",
//             e->arg_u64[0], e->arg_u64[1], e->arg_s32[0], e->arg_s32[1], e->arg_s32[2], e->arg_u64[2]);
//     return 0;
// }

// static int handle_exit_mmap(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mmap: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mmap: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mprotect(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mprotect: %s, len=%llu, prot=%#x\n",
//             e->arg_u64[0], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_mprotect(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mprotect: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mprotect: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_capset(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter capset: %s, header_version=%u, header_pid=%u, data_effective=%#x, data_permitted=%#x, data_inheritable=%#x\n",
//             e->arg_u32[0], e->arg_u32[1], e->arg_u32[2], e->arg_u32[3], e->arg_u32[4]);
//     return 0;
// }

// static int handle_exit_capset(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit capset: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit capset: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_ptrace(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter ptrace: %s, request=%d, pid=%u\n",
//             e->arg_s32[0], e->arg_u32[0]);
//     return 0;
// }

// static int handle_exit_ptrace(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit ptrace: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit ptrace: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_process_vm_readv(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter process_vm_readv: %s, pid=%u, local_iov_len=%llu, remote_iov_len=%llu, flags=%#llx\n",
//             e->arg_u32[0], e->arg_u64[0], e->arg_u64[1], e->arg_u64[2]);
//     return 0;
// }

// static int handle_exit_process_vm_readv(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit process_vm_readv: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit process_vm_readv: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_process_vm_writev(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter process_vm_writev: %s, pid=%u, local_iov_len=%llu, remote_iov_len=%llu, flags=%#llx\n",
//             e->arg_u32[0], e->arg_u64[0], e->arg_u64[1], e->arg_u64[2]);
//     return 0;
// }

// static int handle_exit_process_vm_writev(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit process_vm_writev: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit process_vm_writev: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_init_module(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter init_module: %s, len=%llu, param=%s\n",
//                 e->arg_u64[0], e->arg_str);
//     } else {
//         printf("Enter init_module: %s, len=%llu, failed to read param\n",
//                 e->arg_u64[0]);
//     }
//     return 0;
// }

// static int handle_exit_init_module(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit init_module: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit init_module: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_finit_module(const struct event_t *e, const db_event_t& base_event) {
//     if (e->is_valid) {
//         printf("Enter finit_module: %s, fd=%d, param=%s, flags=%#x\n",
//                 e->arg_s32[0], e->arg_str, e->arg_s32[1]);
//     } else {
//         printf("Enter finit_module: %s, fd=%d, failed to read param\n",
//                 e->arg_s32[0]);
//     }
//     return 0;
// }

// static int handle_exit_finit_module(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit finit_module: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit finit_module: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_delete_module(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter delete_module: %s, name=%s, flags=%#x\n",
//             e->arg_str, e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_delete_module(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit delete_module: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit delete_module: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_munmap(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter munmap: %s, addr=%#llx, len=%llu\n",
//             e->arg_u64[0], e->arg_u64[1]);
//     return 0;
// }

// static int handle_exit_munmap(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit munmap: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit munmap: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mremap(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mremap: %s, old_addr=%#llx, old_len=%llu, new_len=%llu, flags=%#x, new_addr=%#llx\n",
//             e->arg_u64[0], e->arg_u64[1], e->arg_u64[2], e->arg_s32[0], e->arg_u64[3]);
//     return 0;
// }

// static int handle_exit_mremap(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mremap: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mremap: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_madvise(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter madvise: %s, addr=%#llx, len=%llu, advice=%d\n",
//             e->arg_u64[0], e->arg_u64[1], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_madvise(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit madvise: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit madvise: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mlock(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mlock: %s, addr=%#llx, len=%llu\n",
//             e->arg_u64[0], e->arg_u64[1]);
//     return 0;
// }

// static int handle_exit_mlock(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mlock: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mlock: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mlock2(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mlock2: %s, addr=%#llx, len=%llu, flags=%#x\n",
//             e->arg_u64[0], e->arg_u64[1], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_mlock2(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mlock2: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mlock2: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_munlock(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter munlock: %s, addr=%#llx, len=%llu\n",
//             e->arg_u64[0], e->arg_u64[1]);
//     return 0;
// }

// static int handle_exit_munlock(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit munlock: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit munlock: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mlockall(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mlockall: %s, flags=%#x\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_mlockall(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mlockall: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mlockall: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_munlockall(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter munlockall: %s\n", 
//     return 0;
// }

// static int handle_exit_munlockall(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit munlockall: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit munlockall: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_mincore(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter mincore: %s, addr=%#llx, len=%llu\n",
//             e->arg_u64[0], e->arg_u64[1]);
//     return 0;
// }

// static int handle_exit_mincore(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit mincore: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit mincore: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_membarrier(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter membarrier: %s, cmd=%d, flags=%#x, cpu_id=%d\n", 
//             e->arg_s32[0], e->arg_u32[0], e->arg_s32[1]);
//     return 0;
// }

// static int handle_exit_membarrier(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit membarrier: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit membarrier: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_capget(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter capget: %s\n", 
//     return 0;
// }

// static int handle_exit_capget(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit capget: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else if (e->is_valid) {
//         printf("Enter capget: success, %s, header_version=%u, header_pid=%u, data_effective=%#x, data_permitted=%#x, data_inheritable=%#x, ret=%lld\n",
//             e->arg_u32[0], e->arg_u32[1], e->arg_u32[2], e->arg_u32[3], e->arg_u32[4], e->ret);
//     } else {
//         printf("Exit capget: success, %s, failed to read cap values, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_prctl(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter prctl: %s, option=%d\n",
//             e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_prctl(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit prctl: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit prctl: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_arch_prctl(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter arch_prctl: %s, option=%d, addr=%#llx\n",
//             e->arg_s32[0], e->arg_u64[0]);
//     return 0;
// }

// static int handle_exit_arch_prctl(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit arch_prctl: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit arch_prctl: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_kill(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter kill: %s, pid=%u, sig=%d\n",
//             e->arg_u32[0], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_kill(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit kill: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit kill: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_tkill(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter tkill: %s, tid=%u, sig=%d\n",
//             e->arg_u32[0], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_tkill(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit tkill: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit tkill: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

// static int handle_enter_tgkill(const struct event_t *e, const db_event_t& base_event) {
//     printf("Enter tgkill: %s, tgid=%u, tid=%u, sig=%d\n",
//             e->arg_u32[0], e->arg_u32[1], e->arg_s32[0]);
//     return 0;
// }

// static int handle_exit_tgkill(const struct event_t *e, const db_event_t& base_event) {
//     if (e->ret < 0) {
//         printf("Exit tgkill: failed, %s, error_code=%lld\n",
//                 e->ret);
//     } else {
//         printf("Exit tgkill: success, %s, ret=%lld\n",
//                 e->ret);
//     }
//     return 0;
// }

static struct socket_handlers event_handler[MAX_EVENT_ID] = {0};

void init_event_handlers(void) {
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
    // event_handler[__NR_mkdir].enter = handle_enter_mkdir;
    // event_handler[__NR_mkdir].exit = handle_exit_mkdir;
    // event_handler[__NR_mkdirat].enter = handle_enter_mkdirat;
    // event_handler[__NR_mkdirat].exit = handle_exit_mkdirat;
    // event_handler[__NR_rmdir].enter = handle_enter_rmdir;
    // event_handler[__NR_rmdir].exit = handle_exit_rmdir;
    // event_handler[__NR_getcwd].enter = handle_enter_getcwd;
    // event_handler[__NR_getcwd].exit = handle_exit_getcwd;
    // event_handler[__NR_chdir].enter = handle_enter_chdir;
    // event_handler[__NR_chdir].exit = handle_exit_chdir;
    // event_handler[__NR_fchdir].enter = handle_enter_fchdir;
    // event_handler[__NR_fchdir].exit = handle_exit_fchdir;
    // event_handler[__NR_chroot].enter = handle_enter_chroot;
    // event_handler[__NR_chroot].exit = handle_exit_chroot;
    // event_handler[__NR_pivot_root].enter = handle_enter_pivot_root;
    // event_handler[__NR_pivot_root].exit = handle_exit_pivot_root;
    // event_handler[__NR_getdents].enter = handle_enter_getdents;
    // event_handler[__NR_getdents].exit = handle_exit_getdents;
    // event_handler[__NR_getdents64].enter = handle_enter_getdents64;
    // event_handler[__NR_getdents64].exit = handle_exit_getdents64;
    // event_handler[__NR_link].enter = handle_enter_link;
    // event_handler[__NR_link].exit = handle_exit_link;
    // event_handler[__NR_linkat].enter = handle_enter_linkat;
    // event_handler[__NR_linkat].exit = handle_exit_linkat;
    // event_handler[__NR_symlink].enter = handle_enter_symlink;
    // event_handler[__NR_symlink].exit = handle_exit_symlink;
    // event_handler[__NR_symlinkat].enter = handle_enter_symlinkat;
    // event_handler[__NR_symlinkat].exit = handle_exit_symlinkat;
    // event_handler[__NR_unlink].enter = handle_enter_unlink;
    // event_handler[__NR_unlink].exit = handle_exit_unlink;
    // event_handler[__NR_unlinkat].enter = handle_enter_unlinkat;
    // event_handler[__NR_unlinkat].exit = handle_exit_unlinkat;
    // event_handler[__NR_readlink].enter = handle_enter_readlink;
    // event_handler[__NR_readlink].exit = handle_exit_readlink;
    // event_handler[__NR_readlinkat].enter = handle_enter_readlinkat;
    // event_handler[__NR_readlinkat].exit = handle_exit_readlinkat;
    // event_handler[__NR_umask].enter = handle_enter_umask;
    // event_handler[__NR_umask].exit = handle_exit_umask;
    // event_handler[__NR_stat].enter = handle_enter_newstat;
    // event_handler[__NR_stat].exit = handle_exit_newstat;
    // event_handler[__NR_lstat].enter = handle_enter_newlstat;
    // event_handler[__NR_lstat].exit = handle_exit_newlstat;
    // event_handler[__NR_fstat].enter = handle_enter_newfstat;
    // event_handler[__NR_fstat].exit = handle_exit_newfstat;
    // event_handler[__NR_newfstatat].enter = handle_enter_newfstatat;
    // event_handler[__NR_newfstatat].exit = handle_exit_newfstatat;
    // event_handler[__NR_statx].enter = handle_enter_statx;
    // event_handler[__NR_statx].exit = handle_exit_statx;
    // event_handler[__NR_statfs].enter = handle_enter_statfs;
    // event_handler[__NR_statfs].exit = handle_exit_statfs;
    // event_handler[__NR_fstatfs].enter = handle_enter_fstatfs;
    // event_handler[__NR_fstatfs].exit = handle_exit_fstatfs;
    // event_handler[__NR_chmod].enter = handle_enter_chmod;
    // event_handler[__NR_chmod].exit = handle_exit_chmod;
    // event_handler[__NR_fchmod].enter = handle_enter_fchmod;
    // event_handler[__NR_fchmod].exit = handle_exit_fchmod;
    // event_handler[__NR_fchmodat].enter = handle_enter_fchmodat;
    // event_handler[__NR_fchmodat].exit = handle_exit_fchmodat;
    // event_handler[__NR_chown].enter = handle_enter_chown;
    // event_handler[__NR_chown].exit = handle_exit_chown;
    // event_handler[__NR_lchown].enter = handle_enter_lchown;
    // event_handler[__NR_lchown].exit = handle_exit_lchown;
    // event_handler[__NR_fchown].enter = handle_enter_fchown;
    // event_handler[__NR_fchown].exit = handle_exit_fchown;
    // event_handler[__NR_fchownat].enter = handle_enter_fchownat;
    // event_handler[__NR_fchownat].exit = handle_exit_fchownat;
    // event_handler[__NR_access].enter = handle_enter_access;
    // event_handler[__NR_access].exit = handle_exit_access;
    // event_handler[__NR_faccessat].enter = handle_enter_faccessat;
    // event_handler[__NR_faccessat].exit = handle_exit_faccessat;
    // event_handler[__NR_fcntl].enter = handle_enter_fcntl;
    // event_handler[__NR_fcntl].exit = handle_exit_fcntl;
    // event_handler[__NR_dup].enter = handle_enter_dup;
    // event_handler[__NR_dup].exit = handle_exit_dup;
    // event_handler[__NR_dup2].enter = handle_enter_dup2;
    // event_handler[__NR_dup2].exit = handle_exit_dup2;
    // event_handler[__NR_dup3].enter = handle_enter_dup3;
    // event_handler[__NR_dup3].exit = handle_exit_dup3;
    // event_handler[__NR_flock].enter = handle_enter_flock;
    // event_handler[__NR_flock].exit = handle_exit_flock;
    // event_handler[__NR_read].enter = handle_enter_read;
    // event_handler[__NR_read].exit = handle_exit_read;
    // event_handler[__NR_pread64].enter = handle_enter_pread64;
    // event_handler[__NR_pread64].exit = handle_exit_pread64;
    // event_handler[__NR_readv].enter = handle_enter_readv;
    // event_handler[__NR_readv].exit = handle_exit_readv;
    // event_handler[__NR_preadv].enter = handle_enter_preadv;
    // event_handler[__NR_preadv].exit = handle_exit_preadv;
    // event_handler[__NR_preadv2].enter = handle_enter_preadv2;
    // event_handler[__NR_preadv2].exit = handle_exit_preadv2;
    // event_handler[__NR_write].enter = handle_enter_write;
    // event_handler[__NR_write].exit = handle_exit_write;
    // event_handler[__NR_pwrite64].enter = handle_enter_pwrite64;
    // event_handler[__NR_pwrite64].exit = handle_exit_pwrite64;
    // event_handler[__NR_writev].enter = handle_enter_writev;
    // event_handler[__NR_writev].exit = handle_exit_writev;
    // event_handler[__NR_pwritev].enter = handle_enter_pwritev;
    // event_handler[__NR_pwritev].exit = handle_exit_pwritev;
    // event_handler[__NR_pwritev2].enter = handle_enter_pwritev2;
    // event_handler[__NR_pwritev2].exit = handle_exit_pwritev2;
    // event_handler[__NR_lseek].enter = handle_enter_lseek;
    // event_handler[__NR_lseek].exit = handle_exit_lseek;
    // event_handler[__NR_sendfile].enter = handle_enter_sendfile64;
    // event_handler[__NR_sendfile].exit = handle_exit_sendfile64;
    // event_handler[__NR_inotify_init].enter = handle_enter_inotify_init;
    // event_handler[__NR_inotify_init].exit = handle_exit_inotify_init;
    // event_handler[__NR_inotify_init1].enter = handle_enter_inotify_init1;
    // event_handler[__NR_inotify_init1].exit = handle_exit_inotify_init1;
    // event_handler[__NR_inotify_add_watch].enter = handle_enter_inotify_add_watch;
    // event_handler[__NR_inotify_add_watch].exit = handle_exit_inotify_add_watch;
    // event_handler[__NR_inotify_rm_watch].enter = handle_enter_inotify_rm_watch;
    // event_handler[__NR_inotify_rm_watch].exit = handle_exit_inotify_rm_watch;
    // event_handler[__NR_fanotify_init].enter = handle_enter_fanotify_init;
    // event_handler[__NR_fanotify_init].exit = handle_exit_fanotify_init;
    // event_handler[__NR_fanotify_mark].enter = handle_enter_fanotify_mark;
    // event_handler[__NR_fanotify_mark].exit = handle_exit_fanotify_mark;
    // event_handler[__NR_mount].enter = handle_enter_mount;
    // event_handler[__NR_mount].exit = handle_exit_mount;
    // event_handler[__NR_umount2].enter = handle_enter_umount;
    // event_handler[__NR_umount2].exit = handle_exit_umount;
    // event_handler[__NR_move_mount].enter = handle_enter_move_mount;
    // event_handler[__NR_move_mount].exit = handle_exit_move_mount;
    // event_handler[__NR_clone].enter = handle_enter_clone;
    // event_handler[__NR_clone].exit = handle_exit_clone;
    // event_handler[__NR_clone3].enter = handle_enter_clone3;
    // event_handler[__NR_clone3].exit = handle_exit_clone3;
    // event_handler[__NR_fork].enter = handle_enter_fork;
    // event_handler[__NR_fork].exit = handle_exit_fork;
    // event_handler[__NR_vfork].enter = handle_enter_vfork;
    // event_handler[__NR_vfork].exit = handle_exit_vfork;
    // event_handler[__NR_execve].enter = handle_enter_execve;
    // event_handler[__NR_execve].exit = handle_exit_execve;
    // event_handler[__NR_execveat].enter = handle_enter_execveat;
    // event_handler[__NR_execveat].exit = handle_exit_execveat;
    // event_handler[__NR_exit].enter = handle_enter_exit;
    // event_handler[__NR_exit].exit = handle_exit_exit;
    // event_handler[__NR_exit_group].enter = handle_enter_exit_group;
    // event_handler[__NR_exit_group].exit = handle_exit_exit_group;
    // event_handler[__NR_wait4].enter = handle_enter_wait4;
    // event_handler[__NR_wait4].exit = handle_exit_wait4;
    // event_handler[__NR_waitid].enter = handle_enter_waitid;
    // event_handler[__NR_waitid].exit = handle_exit_waitid;
    // event_handler[__NR_getpid].enter = handle_enter_getpid;
    // event_handler[__NR_getpid].exit = handle_exit_getpid;
    // event_handler[__NR_getppid].enter = handle_enter_getppid;
    // event_handler[__NR_getppid].exit = handle_exit_getppid;
    // event_handler[__NR_gettid].enter = handle_enter_gettid;
    // event_handler[__NR_gettid].exit = handle_exit_gettid;
    // event_handler[__NR_setsid].enter = handle_enter_setsid;
    // event_handler[__NR_setsid].exit = handle_exit_setsid;
    // event_handler[__NR_getsid].enter = handle_enter_getsid;
    // event_handler[__NR_getsid].exit = handle_exit_getsid;
    // event_handler[__NR_setpgid].enter = handle_enter_setpgid;
    // event_handler[__NR_setpgid].exit = handle_exit_setpgid;
    // event_handler[__NR_getpgid].enter = handle_enter_getpgid;
    // event_handler[__NR_getpgid].exit = handle_exit_getpgid;
    // event_handler[__NR_getpgrp].enter = handle_enter_getpgrp;
    // event_handler[__NR_getpgrp].exit = handle_exit_getpgrp;
    // event_handler[__NR_setuid].enter = handle_enter_setuid;
    // event_handler[__NR_setuid].exit = handle_exit_setuid;
    // event_handler[__NR_getuid].enter = handle_enter_getuid;
    // event_handler[__NR_getuid].exit = handle_exit_getuid;
    // event_handler[__NR_setgid].enter = handle_enter_setgid;
    // event_handler[__NR_setgid].exit = handle_exit_setgid;
    // event_handler[__NR_getgid].enter = handle_enter_getgid;
    // event_handler[__NR_getgid].exit = handle_exit_getgid;
    // event_handler[__NR_setresuid].enter = handle_enter_setresuid;
    // event_handler[__NR_setresuid].exit = handle_exit_setresuid;
    // event_handler[__NR_getresuid].enter = handle_enter_getresuid;
    // event_handler[__NR_getresuid].exit = handle_exit_getresuid;
    // event_handler[__NR_setresgid].enter = handle_enter_setresgid;
    // event_handler[__NR_setresgid].exit = handle_exit_setresgid;
    // event_handler[__NR_getresgid].enter = handle_enter_getresgid;
    // event_handler[__NR_getresgid].exit = handle_exit_getresgid;
    // event_handler[__NR_setreuid].enter = handle_enter_setreuid;
    // event_handler[__NR_setreuid].exit = handle_exit_setreuid;
    // event_handler[__NR_setregid].enter = handle_enter_setregid;
    // event_handler[__NR_setregid].exit = handle_exit_setregid;
    // event_handler[__NR_geteuid].enter = handle_enter_geteuid;
    // event_handler[__NR_geteuid].exit = handle_exit_geteuid;
    // event_handler[__NR_getegid].enter = handle_enter_getegid;
    // event_handler[__NR_getegid].exit = handle_exit_getegid;
    // event_handler[__NR_setgroups].enter = handle_enter_setgroups;
    // event_handler[__NR_setgroups].exit = handle_exit_setgroups;
    // event_handler[__NR_getgroups].enter = handle_enter_getgroups;
    // event_handler[__NR_getgroups].exit = handle_exit_getgroups;
    // event_handler[__NR_setns].enter = handle_enter_setns;
    // event_handler[__NR_setns].exit = handle_exit_setns;
    // event_handler[__NR_setrlimit].enter = handle_enter_setrlimit;
    // event_handler[__NR_setrlimit].exit = handle_exit_setrlimit;
    // event_handler[__NR_getrlimit].enter = handle_enter_getrlimit;
    // event_handler[__NR_getrlimit].exit = handle_exit_getrlimit;
    // event_handler[__NR_prlimit64].enter = handle_enter_prlimit64;
    // event_handler[__NR_prlimit64].exit = handle_exit_prlimit64;
    // event_handler[__NR_getrusage].enter = handle_enter_getrusage;
    // event_handler[__NR_getrusage].exit = handle_exit_getrusage;
    // event_handler[__NR_setpriority].enter = handle_enter_setpriority;
    // event_handler[__NR_setpriority].exit = handle_exit_setpriority;
    // event_handler[__NR_getpriority].enter = handle_enter_getpriority;
    // event_handler[__NR_getpriority].exit = handle_exit_getpriority;
    // event_handler[__NR_ioprio_set].enter = handle_enter_ioprio_set;
    // event_handler[__NR_ioprio_set].exit = handle_exit_ioprio_set;
    // event_handler[__NR_ioprio_get].enter = handle_enter_ioprio_get;
    // event_handler[__NR_ioprio_get].exit = handle_exit_ioprio_get;
    // event_handler[__NR_mmap].enter = handle_enter_mmap;
    // event_handler[__NR_mmap].exit = handle_exit_mmap;
    // event_handler[__NR_mprotect].enter = handle_enter_mprotect;
    // event_handler[__NR_mprotect].exit = handle_exit_mprotect;
    // event_handler[__NR_capset].enter = handle_enter_capset;
    // event_handler[__NR_capset].exit = handle_exit_capset;
    // event_handler[__NR_ptrace].enter = handle_enter_ptrace;
    // event_handler[__NR_ptrace].exit = handle_exit_ptrace;
    // event_handler[__NR_process_vm_readv].enter = handle_enter_process_vm_readv;
    // event_handler[__NR_process_vm_readv].exit = handle_exit_process_vm_readv;
    // event_handler[__NR_process_vm_writev].enter = handle_enter_process_vm_writev;
    // event_handler[__NR_process_vm_writev].exit = handle_exit_process_vm_writev;
    // event_handler[__NR_init_module].enter = handle_enter_init_module;
    // event_handler[__NR_init_module].exit = handle_exit_init_module;
    // event_handler[__NR_finit_module].enter = handle_enter_finit_module;
    // event_handler[__NR_finit_module].exit = handle_exit_finit_module;
    // event_handler[__NR_delete_module].enter = handle_enter_delete_module;
    // event_handler[__NR_delete_module].exit = handle_exit_delete_module;
    // event_handler[__NR_munmap].enter = handle_enter_munmap;
    // event_handler[__NR_munmap].exit = handle_exit_munmap;
    // event_handler[__NR_mremap].enter = handle_enter_mremap;
    // event_handler[__NR_mremap].exit = handle_exit_mremap;
    // event_handler[__NR_madvise].enter = handle_enter_madvise;
    // event_handler[__NR_madvise].exit = handle_exit_madvise;
    // event_handler[__NR_mlock].enter = handle_enter_mlock;
    // event_handler[__NR_mlock].exit = handle_exit_mlock;
    // event_handler[__NR_mlock2].enter = handle_enter_mlock2;
    // event_handler[__NR_mlock2].exit = handle_exit_mlock2;
    // event_handler[__NR_munlock].enter = handle_enter_munlock;
    // event_handler[__NR_munlock].exit = handle_exit_munlock;
    // event_handler[__NR_mlockall].enter = handle_enter_mlockall;
    // event_handler[__NR_mlockall].exit = handle_exit_mlockall;
    // event_handler[__NR_munlockall].enter = handle_enter_munlockall;
    // event_handler[__NR_munlockall].exit = handle_exit_munlockall;
    // event_handler[__NR_mincore].enter = handle_enter_mincore;
    // event_handler[__NR_mincore].exit = handle_exit_mincore;
    // event_handler[__NR_membarrier].enter = handle_enter_membarrier;
    // event_handler[__NR_membarrier].exit = handle_exit_membarrier;
    // event_handler[__NR_capget].enter = handle_enter_capget;
    // event_handler[__NR_capget].exit = handle_exit_capget;
    // event_handler[__NR_prctl].enter = handle_enter_prctl;
    // event_handler[__NR_prctl].exit = handle_exit_prctl;
    // event_handler[__NR_arch_prctl].enter = handle_enter_arch_prctl;
    // event_handler[__NR_arch_prctl].exit = handle_exit_arch_prctl;
    // event_handler[__NR_kill].enter = handle_enter_kill;
    // event_handler[__NR_kill].exit = handle_exit_kill;
    // event_handler[__NR_tkill].enter = handle_enter_tkill;
    // event_handler[__NR_tkill].exit = handle_exit_tkill;
    // event_handler[__NR_tgkill].enter = handle_enter_tgkill;
    // event_handler[__NR_tgkill].exit = handle_exit_tgkill;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = (struct event_t *)data;

    db_event_t base_event = get_str(&e->task, boot_time);
    
    struct socket_handlers *handlers = &event_handler[e->task.event_id];
    event_handler_t handler = e->is_enter ? handlers->enter : handlers->exit;
    if (handler) {
        base_event.is_enter = e->is_enter;
        return handler(e, base_event);
    }
    return 0;
}