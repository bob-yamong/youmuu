#ifndef POLICY_MAP_STRUCTS_H
#define POLICY_MAP_STRUCTS_H

#define TASK_COMM_LEN 16
#define MAX_UID_LIST 30
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
    SECID_KERNEL_MODULE_REQUEST,
    SECID_KERNEL_READ_FILE,
    SECID_BPRM_CREDS_FROM_FILE,
    SECID_SOCKET_CREATE,
    SECID_SOCKET_ACCEPT,
    SECID_FILE_PERMISSION,
    SECID_CAPABLE,
    SECID_PATH_MKNOD,
    SECID_PATH_RMDIR,
    SECID_PATH_UNLINK,
    SECID_PATH_SYMLINK,
    SECID_PATH_MKDIR,
    SECID_PATH_LINK,
    SECID_PATH_RENAME,
    SECID_PATH_CHMOD,
    SECID_PATH_TRUNCATE,
    SECID_MMAP_FILE
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
#define POLICY_AUDIT        (1 << 27)  // 감사 로깅 활성화
#define POLICY_DENY         (1 << 28)  // 명시적 거부 (기본 허용 시)
#define POLICY_ALLOW        (1 << 29)  // 명시적 허용 (기본 거부 시)
#define POLICY_OWNER        (1 << 30)  // 소유자에게만 적용
#define POLICY_RECURSIVE    (1 << 31)  // 재귀적으로 적용 (디렉토리 등)

// 파일 관련 플래그
#define POLICY_FILE_READ    (1 << 0)   // 파일 읽기 허용
#define POLICY_FILE_WRITE   (1 << 1)   // 파일 쓰기 허용
#define POLICY_FILE_EXEC    (1 << 2)   // 파일 실행 허용
#define POLICY_FILE_APPEND  (1 << 3)   // 파일 추가 허용
#define POLICY_FILE_RENAME  (1 << 4)   // 파일 이름 변경 허용
#define POLICY_FILE_DELETE  (1 << 5)   // 파일 삭제 허용
struct file_policy {
    char path[MAX_PATH_LENGTH];
    int uid[MAX_UID_LIST];
    __u32 flags;
};

// 네트워크 관련 플래그
#define POLICY_NET_CONNECT  (1 << 6)   // 네트워크 연결 허용
#define POLICY_NET_BIND     (1 << 7)   // 포트 바인딩 허용
#define POLICY_NET_ACCEPT   (1 << 8)  // 연결 수락 허용
#define POLICY_NET_SEND     (1 << 9)  // 데이터 전송 허용
#define POLICY_NET_RECV     (1 << 10)  // 데이터 수신 허용
struct network_policy {
    __be32 ip;
    __be32 subnet_mask;
    __be16 port;
    __u8 protocol;
    int uid[MAX_UID_LIST];
    __u32 flags;
};

// 프로세스 관련 플래그
#define POLICY_PROC_FORK    (1 << 11)  // 프로세스 포크 허용
#define POLICY_PROC_EXEC    (1 << 12)  // 새 프로그램 실행 허용
#define POLICY_PROC_KILL    (1 << 13)  // 프로세스 종료 허용
#define POLICY_PROC_PTRACE  (1 << 14)  // ptrace 사용 허용
struct process_policy {
    char comm[16];
    int uid[MAX_UID_LIST];
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

#endif /* __SHARED_H */