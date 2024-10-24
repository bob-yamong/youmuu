#ifndef STRUCTS_H
#define STRUCTS_H

struct current_task  {
    __u64 count;
    __u64 timestamp;
    __u64 cgroup_id;
    __u32 ns_id;
    __u32 ppid;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
};

struct event_t {
    struct current_task task;
    __s64 event_id;
    __s64 ret;

    __s32 arg_s32[6];
    __u32 arg_u32[6];
    __u64 arg_u64[6];
    __u8 arg_str[256];

    bool is_enter;
    bool is_valid;
    bool is_null;

    __u32 ip;
    __u16 port;
    __u16 addr_family;
    __u8 ipv6_addr[16];
};

struct event_key {
    __u64 ns_id;
    __s32 event_id;
    char argument[256];
};

struct map_key {
    __u32 pid;
    __u32 tid;
    __u32 ns_id;
};

struct getsockopt_args {
    void *optval_ptr;
    __u32 *optlen_ptr;
};

struct sock_addr_args {
    void *addr_ptr;
    __u64 *addrlen_ptr;
};

struct msg_args {
    struct msghdr *msg_ptr;
};

struct poll_args {
    struct pollfd *fds;
};

struct timespec_args {
    __kernel_time64_t tv_sec;
    long tv_nsec;
};

struct epoll_args {
    struct epoll_event *events;
};

struct EventEntry {
    const char *name;
    __u32 id;
};

#endif