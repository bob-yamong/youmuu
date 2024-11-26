#ifndef MAP_H
#define MAP_H

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);           // container index (pid_namespace)
    __type(value, __s32[120]);    // syscall IDs array
} syscall_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct event_key);
    __type(value, __u8);
} event_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, char[256]);
} buf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, __u64);
} socketpair_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct getsockopt_args);
} getsockopt_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct sock_addr_args);
} getsockname_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct sock_addr_args);
} getpeername_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct sock_addr_args);
} accept_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct sock_addr_args);
} accept4_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct sock_addr_args);
} recvfrom_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, __u64);
} recvmsg_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, __u64);
} getdents_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, __u64);
} getdents64_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct resuid_args);
} resuid_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct resgid_args);
} resgid_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, __u64);
} getrlimit_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct map_key);
    __type(value, struct capget_args);
} capget_args_map SEC(".maps");

#endif