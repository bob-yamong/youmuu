#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CONTAINERS 1000
#define MAX_POLICY_SIZE 1024
#define MAX_PATH_LENGTH 256
#define MAX_POLICIES_PER_CONTAINER 64

enum policy_type {
    POLICY_FILE,
    POLICY_NETWORK,
    POLICY_PROCESS
};

struct policy_key {
    u32 pid_ns_id;
    u32 mnt_ns_id;
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
    u32 flags;
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
    u8 protocol;
    u32 flags;
};

// 프로세스 관련 플래그
#define POLICY_PROC_FORK    (1 << 0)  // 프로세스 포크 허용
#define POLICY_PROC_EXEC    (1 << 1)  // 새 프로그램 실행 허용
#define POLICY_PROC_KILL    (1 << 2)  // 프로세스 종료 허용
#define POLICY_PROC_PTRACE  (1 << 3)  // ptrace 사용 허용
struct process_policy {
    char comm[16];
    u32 flags;
};

struct policy_value {
    u32 num_file_policies;
    u32 num_network_policies;
    u32 num_process_policies;
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
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_PATH_LENGTH]);
} path_buffer SEC(".maps");

static __always_inline int match_policy(struct task_struct *task, enum policy_type type, void *data) {
    struct policy_key key = {};
    key.pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (!value)
        return 0;

    // Check source if specified
    if (value->source[0] != '\0') {
        char *source_path = bpf_map_lookup_elem(&path_buffer, &(u32){0});
        if (!source_path)
            return 0;
        
        struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
        struct path exe_path = BPF_CORE_READ(exe_file, f_path);
        if (bpf_d_path(&exe_path, source_path, MAX_PATH_LENGTH) <= 0)
            return 0;

        if (bpf_strncmp(value->source, source_path, sizeof(value->source)) != 0)
            return 0;
    }

    switch (type) {
        case POLICY_FILE: {
            char *path = (char *)data;
            #pragma unroll
            for (int i = 0; i < MAX_POLICIES_PER_CONTAINER; i++) {
                if (i >= value->num_file_policies)
                    break;
                if (bpf_strncmp(value->file_policies[i].path, path, MAX_PATH_LENGTH) == 0)
                    return value->file_policies[i].flags;
            }
            break;
        }
        case POLICY_NETWORK: {
            struct network_policy *net = (struct network_policy *)data;
            #pragma unroll
            for (int i = 0; i < MAX_POLICIES_PER_CONTAINER; i++) {
                if (i >= value->num_network_policies)
                    break;
                if (value->network_policies[i].ip == net->ip &&
                    value->network_policies[i].port == net->port &&
                    value->network_policies[i].protocol == net->protocol)
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
                if (bpf_strncmp(value->process_policies[i].comm, comm, 16) == 0)
                    return value->process_policies[i].flags;
            }
            break;
        }
    }

    return 0;
}

static __always_inline int get_process_path(struct task_struct *task, char *path_buf, int buf_size) {
    struct file *exe_file;
    struct path exe_path;

    exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (!exe_file)
        return -1;

    exe_path = BPF_CORE_READ(exe_file, f_path);
    return bpf_d_path(&exe_path, path_buf, buf_size);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}