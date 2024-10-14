#ifndef __BPF_H
#define __BPF_H

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vmlinux.h"
#include "shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB 크기
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LENGTH]);
} path_buffer SEC(".maps");

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

#endif
