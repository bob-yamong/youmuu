#ifndef STRUCT_H
#define STRUCT_H

struct current_task  {
    __u64 count;
    __u64 timestamp;
    __u64 cgroup_id;
    __u32 pid_namespace;
    __u32 mnt_namespace;
    __u32 ppid;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u8 comm[16];
};

struct event_t {
    struct current_task task;
    __s64 event_id;
    __s64 ret;

    __s32 arg_s32[6];
    __u32 arg_u32[6];
    __s64 arg_s64[6];
    __u64 arg_u64[6];
    __u8 arg_str[256];
    __u8 arg_str2[256];
    __u8 filesystem_type[32];

    bool is_enter;
    bool is_valid;
    bool is_null;

    __u32 ip;
    __u16 port;
    __u16 addr_family;
    __u8 ipv6_addr[16];
};

struct event_key {
    __s64 event_id;
    __u32 pid_namespace;
};

struct map_key {
    __u32 pid;
    __u32 tid;
    __u32 pid_namespace;
};

struct getsockopt_args {
    void *optval_ptr;
    __u32 *optlen_ptr;
};

struct sock_addr_args {
    void *addr_ptr;
    __u64 *addrlen_ptr;
};

struct timespec_args {
    __kernel_time64_t tv_sec;
    long tv_nsec;
};

struct resuid_args {
    __u64 ruid;
    __u64 euid;
    __u64 suid;
};

struct resgid_args {
    __u64 rgid;
    __u64 egid;
    __u64 sgid;
};

struct capget_args {
    __u64 hdrp;
    __u64 datap;
};

#endif