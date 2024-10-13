#ifndef __SHARED_H
#define __SHARED_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_CONTAINERS 1000
#define MAX_POLICY_SIZE 1024
#define MAX_PATH_LENGTH 256
#define MAX_STRING_SIZE 256
#define MAX_POLICIES_PER_CONTAINER 64

enum section_nr {
	SECID_BPRM_CHECK_SECURITY,
	SECID_FILE_OPEN,
	SECID_SB_MOUNT,
	SECID_SB_REMOUNT,
	SECID_SB_UMOUNT,
	SECID_SOCKET_BIND,
	SECID_SOCKET_CONNECT,
	SECID_TASK_FIX_SETUID,
};

enum policy_type {
    POLICY_FILE,
    POLICY_NETWORK,
    POLICY_PROCESS
};

struct policy_key {
    __u32 pid_ns_id;
    __u32 mnt_ns_id;
};

// 일반 정책 플래그
#define POLICY_AUDIT        (1 << 28)  // 감사 로깅 활성화
#define POLICY_DENY         (1 << 29)  // 명시적 거부 (기본 허용 시)
#define POLICY_ALLOW        (1 << 30)  // 명시적 허용 (기본 거부 시)
#define POLICY_OWNER        (1 << 31)  // 소유자에게만 적용
#define POLICY_RECURSIVE    (1 << 32)  // 재귀적으로 적용 (디렉토리 등)

// 파일 관련 플래그
#define POLICY_FILE_READ    (1 << 0)   // 파일 읽기 허용
#define POLICY_FILE_WRITE   (1 << 1)   // 파일 쓰기 허용
#define POLICY_FILE_EXEC    (1 << 2)   // 파일 실행 허용
#define POLICY_FILE_APPEND  (1 << 3)   // 파일 추가 허용
#define POLICY_FILE_RENAME  (1 << 4)   // 파일 이름 변경 허용
#define POLICY_FILE_DELETE  (1 << 5)   // 파일 삭제 허용
struct file_policy {
    char path[MAX_PATH_LENGTH];
    __u32 flags;
};

// 네트워크 관련 플래그
#define POLICY_NET_CONNECT  (1 << 0)   // 네트워크 연결 허용
#define POLICY_NET_BIND     (1 << 1)   // 포트 바인딩 허용
#define POLICY_NET_ACCEPT   (1 << 2)  // 연결 수락 허용
#define POLICY_NET_SEND     (1 << 3)  // 데이터 전송 허용
#define POLICY_NET_RECV     (1 << 4)  // 데이터 수신 허용
struct network_policy {
    __be32 ip;
    __be16 port;
    __u8 protocol;
    __u32 flags;
};

// 프로세스 관련 플래그
#define POLICY_PROC_FORK    (1 << 0)  // 프로세스 포크 허용
#define POLICY_PROC_EXEC    (1 << 1)  // 새 프로그램 실행 허용
#define POLICY_PROC_KILL    (1 << 2)  // 프로세스 종료 허용
#define POLICY_PROC_PTRACE  (1 << 3)  // ptrace 사용 허용
struct process_policy {
    char comm[16];
    __u32 flags;
};

struct policy_value {
    __u32 num_file_policies;
    __u32 num_network_policies;
    __u32 num_process_policies;
    struct file_policy file_policies[MAX_POLICIES_PER_CONTAINER];
    struct network_policy network_policies[MAX_POLICIES_PER_CONTAINER];
    struct process_policy process_policies[MAX_POLICIES_PER_CONTAINER];
    char source[MAX_PATH_LENGTH];
};

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

typedef struct bufkey {
  char path[MAX_STRING_SIZE];
  char source[MAX_STRING_SIZE];
} bufs_k;

typedef struct {
  __u64 ts;

  // conatiner identifier
  __u32 pid_id;
  __u32 mnt_id;

  // process identifier
  __u32 host_ppid;
  __u32 host_pid;

  __u32 ppid;
  __u32 pid;
  __u32 uid;

  // control group identifier
  __u64 cgroup_id;

  enum section_nr event_id;
  __s64 retval;

  __u8 comm[TASK_COMM_LEN];

  bufs_k data;
} event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB 크기
} events SEC(".maps");

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
  event_data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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

  return 0;
}

#endif /* __SHARED_H */