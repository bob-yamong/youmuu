#ifndef BPF_MAP_STRUCTS_H
#define BPF_MAP_STRUCTS_H

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "policy_map_structs.h"

#define ETH_P_IP 0x0800  // Define IPv4 Ethernet type
#define AF_INET 2    // IPv4
#define AF_INET6 10  // IPv6

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 30);  // 1GB 크기
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LENGTH]);
} path_buffer SEC(".maps");

static __always_inline __u16 bpf_ntohs(__u16 val) {
    return (val << 8) | (val >> 8);
}

static __always_inline __u64 get_cgroup_id() {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return 0;
    }

    int mem_cgrp_id = memory_cgrp_id;

    __u64 cgroup_id = BPF_CORE_READ(cur_tsk, cgroups, subsys[mem_cgrp_id], cgroup, kn, id);

    return cgroup_id;
}

static __always_inline int should_monitor(struct task_struct *task, enum policy_type type) {
    struct policy_key key = {};
    
    key.pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    
    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    
    if (!value) return 0;

    switch (type) {
        case POLICY_FILE: {
            bpf_printk("file policy num:%d from pid_ns_id: %u, mnt_ns_id: %u\n", value->num_file_policies, key.pid_ns_id, key.mnt_ns_id);
            if (value->num_file_policies > 0) return 1;
            break;
        }
        case POLICY_NETWORK: {
            bpf_printk("network policy num:%d from pid_ns_id: %u, mnt_ns_id: %u\n", value->num_network_policies, key.pid_ns_id, key.mnt_ns_id);
            if (value->num_network_policies > 0) return 1;
            break;
        }
        case POLICY_PROCESS: {
            bpf_printk("process policy num:%d from pid_ns_id: %u, mnt_ns_id: %u\n", value->num_process_policies, key.pid_ns_id, key.mnt_ns_id);
            if (value->num_process_policies > 0) return 1;
            break;
        }
    }
    return 0;
}

// Custom strncmp function for BPF
static __always_inline int compare_strings(const char *a, const char *b, __u32 len, __u32 flags) {
    bool is_recursive = flags & POLICY_RECURSIVE;

    for (__u32 i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            if (is_recursive && a[i] == '\0' && i > 0 && a[i-1] == '/') {
                return 0;  
            }
            return 1; 
        }
        if (a[i] == '\0' && b[i] == '\0') return 0;
    }
    return 1; 
}

static __always_inline int get_process_path(char *path_buf, int buf_size) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct file *exe_file;
        struct mm_struct *mm;
        bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
        if (mm) {
            struct file *exe_file;
            bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file);
            if (exe_file) {
                // exe_file 처리
            } else {
                __builtin_memcpy(path_buf, "<no_exe>", 9);
            }
        } else {
            __builtin_memcpy(path_buf, "<no_mm>", 8);
        }
        if (exe_file) {
            struct dentry *exe_dentry;
            bpf_probe_read_kernel(&exe_dentry, sizeof(exe_dentry), &exe_file->f_path.dentry);
            if (exe_dentry) {
                bpf_probe_read_kernel_str(path_buf, sizeof(path_buf), exe_dentry->d_name.name);
            } else {
                __builtin_memcpy(path_buf, "<unknown>", 10);
            }
        } else {
            __builtin_memcpy(path_buf, "<no_exe>", 9);
        }
    } else {
        __builtin_memcpy(path_buf, "<no_task>", 10);
    }
    return 0;
}

static __always_inline __u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline int init_context(event *event_data) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (!task)
    return -1;

  event_data->ts = bpf_ktime_get_ns();
  
  event_data->uid = bpf_get_current_uid_gid() >> 32;
  event_data->cgroup_id = get_cgroup_id();

  // Use BPF_CORE_READ for accessing task struct members
  event_data->host_ppid = BPF_CORE_READ(task, real_parent, tgid);
  event_data->host_pid = bpf_get_current_pid_tgid() >> 32;

  __u32 pid = get_task_pid_vnr(BPF_CORE_READ(task, group_leader));
  if (event_data->host_pid == pid) { // host
    event_data->pid_id = 0;
    event_data->mnt_id = 0;

    event_data->ppid = event_data->host_ppid;
    event_data->pid = event_data->host_pid;
  } else { // container
    event_data->pid_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    event_data->mnt_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    event_data->ppid = get_task_pid_vnr(BPF_CORE_READ(task, real_parent));
    event_data->pid = pid;
  }
  __builtin_memset(event_data->comm, 0, sizeof(event_data->comm));
  bpf_get_current_comm(&event_data->comm, sizeof(event_data->comm));

  return 0;
}

static __always_inline __u32 match_policy(struct task_struct *task, enum policy_type type, void *data) {
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct policy_key key = {};
    
    key.pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    
    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    
    // bpf_printk("match policy request from pid_ns_id: %u, mnt_ns_id: %u\n", key.pid_ns_id, key.mnt_ns_id);
    if (!value) return 0;
    // bpf_printk("start comparing from pid_ns_id: %u, mnt_ns_id: %u\n", key.pid_ns_id, key.mnt_ns_id);

    switch (type) {
        case POLICY_FILE: {
            char *path = (char *)data;
            #pragma unroll
            for (int i = 0; i < MAX_POLICIES_PER_CONTAINER; i++) {
                if (i >= value->num_file_policies)
                    break;
                __u32 flags = value->file_policies[i].flags;  // 정책 플래그 가져오기
                if (compare_strings(value->file_policies[i].path, path, MAX_PATH_LENGTH,flags) == 0)
                    return value->file_policies[i].flags;
            }
            break;
        }
        case POLICY_NETWORK: {
            bpf_printk("network policy num:%d from pid_ns_id: %u, mnt_ns_id: %u\n", value->num_network_policies, key.pid_ns_id, key.mnt_ns_id);
            struct network_policy *net = (struct network_policy *)data;
            #pragma unroll
            for (int i = 0; i < MAX_POLICIES_PER_CONTAINER; i++) {
                if (i >= value->num_network_policies)
                    break;
                bpf_printk("network policy ip:%u, port:%u, protocol:%u, flags:%u from pid_ns_id: %u, mnt_ns_id: %u\n", value->network_policies[i].ip, value->network_policies[i].port, value->network_policies[i].protocol, value->network_policies[i].flags, key.pid_ns_id, key.mnt_ns_id);
                if (value->network_policies[i].ip == net->ip &&
                    (value->network_policies[i].port == net->port || value->network_policies[i].port == 0) &&
                    (value->network_policies[i].protocol == net->protocol || value->network_policies[i].protocol == 0))
                    return value->network_policies[i].flags;
            }
            break;
        }
        case POLICY_PROCESS: {
            char *comm = (char *)data;
            #pragma unroll
            for (int i = 0; i < MAX_POLICIES_PER_CONTAINER; i++) {
                if (i >= value->num_process_policies)
                    break;
                if (compare_strings(value->process_policies[i].comm, comm, 16,0) == 0)
                    return value->process_policies[i].flags;
            }
            break;
        }
    }
    return 0;
}

#endif
