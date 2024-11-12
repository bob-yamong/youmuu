#ifndef USER_STRUCT_H
#define USER_STRUCT_H

#include <string>
#include <linux/types.h>
#include <chrono>

struct db_event_t {
    std::chrono::system_clock::time_point timestamp;
    std::string container_name;
    __s32 syscall;
    bool is_enter;
    __u32 pid_namespace;
    __u32 mnt_namespace;
    __u32 ppid;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __s64 ret;
    std::string comm;
    std::string arg0;
    std::string arg1;
    std::string arg2;
    std::string arg3;
    std::string arg4;
    std::string arg5;
    std::string additional_info;
};

#endif