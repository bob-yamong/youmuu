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

map<string, __u32> flags_map = {
    {"POLICY_AUDIT", POLICY_AUDIT},
    {"POLICY_DENY", POLICY_DENY},
    {"POLICY_ALLOW", POLICY_ALLOW},
    {"POLICY_OWNER", POLICY_OWNER},
    {"POLICY_RECURSIVE", POLICY_RECURSIVE},
    {"POLICY_FILE_READ", POLICY_FILE_READ},
    {"POLICY_FILE_WRITE", POLICY_FILE_WRITE},
    {"POLICY_FILE_EXEC", POLICY_FILE_EXEC},
    {"POLICY_FILE_APPEND", POLICY_FILE_APPEND},
    {"POLICY_FILE_RENAME", POLICY_FILE_RENAME},
    {"POLICY_FILE_DELETE", POLICY_FILE_DELETE},
    {"POLICY_NET_CONNECT", POLICY_NET_CONNECT},
    {"POLICY_NET_SRC", POLICY_NET_SRC},
    {"POLICY_NET_DST", POLICY_NET_DST},
    {"POLICY_PROC_FORK", POLICY_PROC_FORK},
    {"POLICY_PROC_EXEC", POLICY_PROC_EXEC},
    {"POLICY_PROC_KILL", POLICY_PROC_KILL},
    {"POLICY_PROC_PTRACE", POLICY_PROC_PTRACE}
};

map<string, __u32> tracepoints_map = {
    {"__NR_socket", __NR_socket},
    {"__NR_socketpair", __NR_socketpair},
    {"__NR_setsockopt", __NR_setsockopt},
    {"__NR_getsockopt", __NR_getsockopt},
    {"__NR_getsockname", __NR_getsockname},
    {"__NR_getpeername", __NR_getpeername},
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
    {"__NR_ioctl", __NR_ioctl},
    {"__NR_poll", __NR_poll},
    {"__NR_ppoll", __NR_ppoll},
    {"__NR_epoll_create", __NR_epoll_create},
    {"__NR_epoll_create1", __NR_epoll_create1},
    {"__NR_epoll_ctl", __NR_epoll_ctl},
    {"__NR_epoll_wait", __NR_epoll_wait},
    {"__NR_epoll_pwait", __NR_epoll_pwait},
    {"__NR_epoll_pwait2", __NR_epoll_pwait2},
    {"__NR_close", __NR_close},
    {"__NR_creat", __NR_creat},
    {"__NR_open", __NR_open},
    {"__NR_openat", __NR_openat},
    {"__NR_openat2", __NR_openat2},
    {"__NR_name_to_handle_at",  __NR_name_to_handle_at},
    {"__NR_open_by_handle_at", __NR_open_by_handle_at},
    {"__NR_memfd_create", __NR_memfd_create},
    {"__NR_mknod", __NR_mknod},
    {"__NR_mknodat", __NR_mknodat},
    {"__NR_rename", __NR_rename},
    {"__NR_renameat", __NR_renameat},
    {"__NR_renameat2", __NR_renameat2},
    {"__NR_truncate", __NR_truncate},
    {"__NR_ftruncate", __NR_ftruncate},
    {"__NR_fallocate", __NR_fallocate},
    {"__NR_mkdir", __NR_mkdir},
    {"__NR_mkdirat", __NR_mkdirat},
    {"__NR_rmdir", __NR_rmdir},
    {"__NR_getcwd", __NR_getcwd},
    {"__NR_chdir", __NR_chdir},
    {"__NR_fchdir", __NR_fchdir},
    {"__NR_chroot", __NR_chroot},
    {"__NR_pivot_root", __NR_pivot_root},
    {"__NR_getdents", __NR_getdents},
    {"__NR_getdents64", __NR_getdents64},
    {"__NR_link", __NR_link},
    {"__NR_linkat", __NR_linkat},
    {"__NR_symlink", __NR_symlink},
    {"__NR_symlinkat", __NR_symlinkat},
    {"__NR_unlink", __NR_unlink},
    {"__NR_unlinkat", __NR_unlinkat},
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
    {"__NR_chmod", __NR_chmod},
    {"__NR_fchmod", __NR_fchmod},
    {"__NR_fchmodat", __NR_fchmodat},
    {"__NR_chown", __NR_chown},
    {"__NR_lchown", __NR_lchown},
    {"__NR_fchown", __NR_fchown},
    {"__NR_fchownat", __NR_fchownat},
    {"__NR_utime", __NR_utime},
    {"__NR_utimes", __NR_utimes},
    {"__NR_futimesat", __NR_futimesat},
    {"__NR_utimensat", __NR_utimensat},
    {"__NR_access", __NR_access},
    {"__NR_faccessat", __NR_faccessat},
    {"__NR_setxattr", __NR_setxattr},
    {"__NR_lsetxattr", __NR_lsetxattr},
    {"__NR_fsetxattr", __NR_fsetxattr},
    {"__NR_getxattr", __NR_getxattr},
    {"__NR_lgetxattr", __NR_lgetxattr},
    {"__NR_fgetxattr", __NR_fgetxattr},
    {"__NR_listxattr", __NR_listxattr},
    {"__NR_llistxattr", __NR_llistxattr},
    {"__NR_flistxattr", __NR_flistxattr},
    {"__NR_removexattr", __NR_removexattr},
    {"__NR_lremovexattr", __NR_lremovexattr},
    {"__NR_fremovexattr", __NR_fremovexattr},
    {"__NR_fcntl", __NR_fcntl},
    {"__NR_dup", __NR_dup},
    {"__NR_dup2", __NR_dup2},
    {"__NR_dup3", __NR_dup3},
    {"__NR_flock", __NR_flock},
    {"__NR_read", __NR_read},
    {"__NR_pread64", __NR_pread64},
    {"__NR_readv", __NR_readv},
    {"__NR_preadv", __NR_preadv},
    {"__NR_preadv2", __NR_preadv2},
    {"__NR_write", __NR_write},
    {"__NR_pwrite64", __NR_pwrite64},
    {"__NR_writev", __NR_writev},
    {"__NR_pwritev", __NR_pwritev},
    {"__NR_pwritev2", __NR_pwritev2},
    {"__NR_lseek", __NR_lseek},
    {"__NR_sendfile", __NR_sendfile},
    {"__NR_inotify_init", __NR_inotify_init},
    {"__NR_inotify_init1", __NR_inotify_init1},
    {"__NR_inotify_add_watch", __NR_inotify_add_watch},
    {"__NR_inotify_rm_watch", __NR_inotify_rm_watch},
    {"__NR_fanotify_init", __NR_fanotify_init},
    {"__NR_fanotify_mark", __NR_fanotify_mark},
    {"__NR_mount", __NR_mount},
    {"__NR_umount2", __NR_umount2},
    {"__NR_move_mount", __NR_move_mount},
    {"__NR_clone", __NR_clone},
    {"__NR_clone3", __NR_clone3},
    {"__NR_fork", __NR_fork},
    {"__NR_vfork", __NR_vfork},
    {"__NR_execve", __NR_execve},
    {"__NR_execveat", __NR_execveat},
    {"__NR_exit", __NR_exit},
    {"__NR_exit_group", __NR_exit_group},
    {"__NR_wait4", __NR_wait4},
    {"__NR_waitid", __NR_waitid},
};


__u32 string_to_flags(vector<string> str_flags){
    __u32 flags = 0;

    for (const auto& str_flag : str_flags) {
        flags |= flags_map[str_flag];
    }

    return flags;
}


vector<string> flags_to_string(__u32 flags){
    vector<string> flags_str;

    for (const auto& flag : flags_map) {
        if (flags & flag.second) {
            flags_str.push_back(flag.first);
        }
    }

    return flags_str;
}

vector<string> tracepoints_to_string(vector<int> tracepoints){
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

vector<int> string_to_tracepoints(vector<string> str_tracepoints){
    vector<int> tracepoints;

    for (const auto& str_tracepoint : str_tracepoints) {
        tracepoints.push_back(tracepoints_map[str_tracepoint]);
    }

    return tracepoints;
}

// IP 주소와 서브넷 마스크를 저장하는 구조체
struct IpAddress {
    uint32_t ip;
    uint32_t subnet_mask;
};

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
    vector<string> tracepoints;
};

struct YamlContainerPolicy {
    string container_name;
    string raw_tp_policy;
    YamlLsmPolicy lsm_policies;
    YamlTracepointPolicy tracepoint_policy;
};

struct YamlPolicy {
    string api_version;
    string name;
    vector<YamlContainerPolicy> containers;
};

// IP 주소 문자열을 정수로 변환하는 함수
IpAddress parse_ip(const string& ip_str) {
    IpAddress result = {0, 0};
    
    size_t slash_pos = ip_str.find('/');
    string ip_part = ip_str.substr(0, slash_pos);
    
    inet_pton(AF_INET, ip_part.c_str(), &result.ip);
    result.ip = ntohl(result.ip);
    
    if (slash_pos != string::npos) {
        int prefix_len = stoi(ip_str.substr(slash_pos + 1));
        if (prefix_len >= 0 && prefix_len <= 32) {
            result.subnet_mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
        }
    } else {
        result.subnet_mask = ~0U;
    }
    
    return result;
}


#endif