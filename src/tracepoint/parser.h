#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <asm/unistd_64.h>

#include "../include/reflect-cpp/include/rfl/thirdparty/yyjson.h"
#include "../include/reflect-cpp/src/yyjson.c"
#include "../include/reflect-cpp/src/reflectcpp_yaml.cpp"
#include "../include/reflect-cpp/src/reflectcpp.cpp"
#include "../include/reflect-cpp/include/rfl/yaml.hpp"

using namespace std;

map<string, __u32> tracepoints_map = {
    {"__NR_socket", __NR_socket},
    {"__NR_socketpair", __NR_socketpair},
    {"__NR_setsockopt", __NR_setsockopt},
    {"__NR_bind", __NR_bind},
    {"__NR_listen", __NR_listen},
    {"__NR_accept", __NR_accept},
    {"__NR_accept4", __NR_accept4},
    {"__NR_connect", __NR_connect},
    {"__NR_shutdown", __NR_shutdown},
    {"__NR_recvfrom", __NR_recvfrom},
    {"__NR_recvmsg", __NR_recvmsg},
    {"__NR_recvmmsg", __NR_recvmmsg},
    {"__NR_sendto", __NR_sendto},
    {"__NR_sendmsg", __NR_sendmsg},
    {"__NR_sendmmsg", __NR_sendmmsg},
    {"__NR_sethostname", __NR_sethostname},
    {"__NR_setdomainname", __NR_setdomainname},

    {"__NR_getsockopt", __NR_getsockopt},
    {"__NR_getsockname", __NR_getsockname},
    {"__NR_getpeername", __NR_getpeername},
    {"__NR_ioctl", __NR_ioctl},

    {"__NR_creat", __NR_creat},
    {"__NR_open", __NR_open},
    {"__NR_openat", __NR_openat},
    {"__NR_openat2", __NR_openat2},
    {"__NR_write", __NR_write},
    {"__NR_pwrite64", __NR_pwrite64},
    {"__NR_writev", __NR_writev},
    {"__NR_pwritev", __NR_pwritev},
    {"__NR_pwritev2", __NR_pwritev2},
    {"__NR_mkdir", __NR_mkdir},
    {"__NR_mkdirat", __NR_mkdirat},
    {"__NR_rmdir", __NR_rmdir},
    {"__NR_chdir", __NR_chdir},
    {"__NR_fchdir", __NR_fchdir},
    {"__NR_chroot", __NR_chroot},
    {"__NR_pivot_root", __NR_pivot_root},
    {"__NR_link", __NR_link},
    {"__NR_linkat", __NR_linkat},
    {"__NR_symlink", __NR_symlink},
    {"__NR_symlinkat", __NR_symlinkat},
    {"__NR_unlink", __NR_unlink},
    {"__NR_unlinkat", __NR_unlinkat},
    {"__NR_rename", __NR_rename},
    {"__NR_renameat", __NR_renameat},
    {"__NR_renameat2", __NR_renameat2},
    {"__NR_chmod", __NR_chmod},
    {"__NR_fchmod", __NR_fchmod},
    {"__NR_fchmodat", __NR_fchmodat},
    {"__NR_chown", __NR_chown},
    {"__NR_lchown", __NR_lchown},
    {"__NR_fchown", __NR_fchown},
    {"__NR_fchownat", __NR_fchownat},
    {"__NR_mount", __NR_mount},
    {"__NR_umount2", __NR_umount2},
    {"__NR_move_mount", __NR_move_mount},
    
    {"__NR_read", __NR_read},
    {"__NR_pread64", __NR_pread64},
    {"__NR_readv", __NR_readv},
    {"__NR_preadv", __NR_preadv},
    {"__NR_preadv2", __NR_preadv2},
    {"__NR_close", __NR_close},
    {"__NR_dup", __NR_dup},
    {"__NR_dup2", __NR_dup2},
    {"__NR_dup3", __NR_dup3},
    {"__NR_flock", __NR_flock},
    {"__NR_name_to_handle_at",  __NR_name_to_handle_at},
    {"__NR_open_by_handle_at", __NR_open_by_handle_at},
    {"__NR_memfd_create", __NR_memfd_create},
    {"__NR_mknod", __NR_mknod},
    {"__NR_mknodat", __NR_mknodat},
    {"__NR_truncate", __NR_truncate},
    {"__NR_ftruncate", __NR_ftruncate},
    {"__NR_fallocate", __NR_fallocate},
    {"__NR_getcwd", __NR_getcwd},
    {"__NR_getdents", __NR_getdents},
    {"__NR_getdents64", __NR_getdents64},
    {"__NR_readlink", __NR_readlink},
    {"__NR_readlinkat", __NR_readlinkat},
    {"__NR_umask", __NR_umask},
    {"__NR_stat", __NR_stat},
    {"__NR_lstat", __NR_lstat},
    {"__NR_fstat", __NR_fstat},
    {"__NR_newfstatat", __NR_newfstatat},
    {"__NR_statx", __NR_statx},
    {"__NR_statfs", __NR_statfs},
    {"__NR_fstatfs", __NR_fstatfs},
    {"__NR_access", __NR_access},
    {"__NR_faccessat", __NR_faccessat},
    {"__NR_lseek", __NR_lseek},
    {"__NR_sendfile", __NR_sendfile},
    {"__NR_inotify_init", __NR_inotify_init},
    {"__NR_inotify_init1", __NR_inotify_init1},
    {"__NR_inotify_add_watch", __NR_inotify_add_watch},
    {"__NR_inotify_rm_watch", __NR_inotify_rm_watch},
    {"__NR_fanotify_init", __NR_fanotify_init},
    {"__NR_fanotify_mark", __NR_fanotify_mark},
    {"__NR_fcntl", __NR_fcntl},

    {"__NR_clone", __NR_clone},
    {"__NR_clone3", __NR_clone3},
    {"__NR_fork", __NR_fork},
    {"__NR_vfork", __NR_vfork},
    {"__NR_execve", __NR_execve},
    {"__NR_execveat", __NR_execveat},
    {"__NR_setsid", __NR_setsid},
    {"__NR_setpgid", __NR_setpgid},
    {"__NR_setuid", __NR_setuid},
    {"__NR_setgid", __NR_setgid},
    {"__NR_setresuid", __NR_setresuid},
    {"__NR_setresgid", __NR_setresgid},
    {"__NR_setreuid", __NR_setreuid},
    {"__NR_setregid", __NR_setregid},
    {"__NR_setgroups", __NR_setgroups},
    {"__NR_setns", __NR_setns},
    {"__NR_capset", __NR_capset},
    {"__NR_mmap", __NR_mmap},
    {"__NR_mprotect", __NR_mprotect},
    {"__NR_ptrace", __NR_ptrace},
    {"__NR_process_vm_readv", __NR_process_vm_readv},
    {"__NR_process_vm_writev", __NR_process_vm_writev},
    {"__NR_init_module", __NR_init_module},
    {"__NR_delete_module", __NR_delete_module},
    {"__NR_finit_module", __NR_finit_module},

    {"__NR_exit", __NR_exit},
    {"__NR_exit_group", __NR_exit_group},
    {"__NR_wait4", __NR_wait4},
    {"__NR_waitid", __NR_waitid},
    {"__NR_getpid", __NR_getpid},
    {"__NR_getppid", __NR_getppid},
    {"__NR_gettid", __NR_gettid},
    {"__NR_getsid", __NR_getsid},
    {"__NR_getpgid", __NR_getpgid},
    {"__NR_getpgrp", __NR_getpgrp},
    {"__NR_getuid", __NR_getuid},
    {"__NR_getgid", __NR_getgid},
    {"__NR_getresuid", __NR_getresuid},
    {"__NR_getresgid", __NR_getresgid},
    {"__NR_geteuid", __NR_geteuid},
    {"__NR_getegid", __NR_getegid},
    {"__NR_getgroups", __NR_getgroups},
    {"__NR_setrlimit", __NR_setrlimit},
    {"__NR_getrlimit", __NR_getrlimit},
    {"__NR_prlimit64", __NR_prlimit64},
    {"__NR_getrusage", __NR_getrusage},
    {"__NR_setpriority", __NR_setpriority},
    {"__NR_getpriority", __NR_getpriority},
    {"__NR_ioprio_set", __NR_ioprio_set},
    {"__NR_ioprio_get", __NR_ioprio_get},
    {"__NR_brk", __NR_brk},
    {"__NR_munmap", __NR_munmap},
    {"__NR_mremap", __NR_mremap},
    {"__NR_madvise", __NR_madvise},
    {"__NR_mlock", __NR_mlock},
    {"__NR_mlock2", __NR_mlock2},
    {"__NR_mlockall", __NR_mlockall},
    {"__NR_munlock", __NR_munlock},
    {"__NR_munlockall", __NR_munlockall},
    {"__NR_membarrier", __NR_membarrier},
    {"__NR_capget", __NR_capget},
    {"__NR_set_thread_area", __NR_set_thread_area},
    {"__NR_get_thread_area", __NR_get_thread_area},
    {"__NR_set_tid_address", __NR_set_tid_address},
    {"__NR_arch_prctl", __NR_arch_prctl}
};

vector<string> syscalls_to_string(vector<int> tracepoints){
    vector<string> tracepoints_str;

    map<int, string> new_tracepoints_map;
    for (const auto& tracepoint : tracepoints_map) {
        new_tracepoints_map[tracepoint.second] = tracepoint.first;
    }

    for (auto& tracepoint : tracepoints){
        tracepoints_str.push_back(new_tracepoints_map[tracepoint]);
    }

    return tracepoints_str;
}

vector<int> string_to_syscalls(vector<string> str_tracepoints){
    vector<int> tracepoints;

    for (const auto& str_tracepoint : str_tracepoints) {
        tracepoints.push_back(tracepoints_map[str_tracepoint]);
    }

    return tracepoints;
}

// Policy 관련 구조체 정의
struct YamlNetworkPolicy {
    string ip;
    int port;
    int protocol;
    vector<string> flags;
    vector<int> uid;
};

struct YamlFilePolicy {
    string path;
    vector<string> flags;
    vector<int> uid;
};

struct YamlProcessPolicy {
    string comm;
    vector<string> flags;
    vector<int> uid;
};

struct YamlLsmPolicy {
    vector<YamlFilePolicy> file;
    vector<YamlNetworkPolicy> network;
    vector<YamlProcessPolicy> process;
};

struct YamlTracepointPolicy {
    vector<string> syscalls;
};

struct YamlContainerPolicy {
    string container_name;
    YamlLsmPolicy lsm_policies;
    YamlTracepointPolicy tracepoint_policy;
};

struct YamlPolicy {
    string api_version;
    string name;
    vector<YamlContainerPolicy> containers;
};

#endif