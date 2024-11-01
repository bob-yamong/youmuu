#ifndef EVENT_H
#define EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS 10
#define MAX_ARG_LEN 128
#define MAX_CGROUP_NAME_LEN 64  // cgroup 이름의 최대 길이 정의

struct event {
    __u64 timestamp;
    __u64 cnt;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 syscall_nr;
    char comm[TASK_COMM_LEN];
    char syscall[16];
    __u64 args[6];
    char filename[MAX_FILENAME_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
    __u64 cgroup_id;
    char cgroup_name[MAX_CGROUP_NAME_LEN];  // cgroup 이름 추가
}__attribute__((packed));
// struct event {
//     __u64 timestamp;
//     __u64 cnt;
//     __u32 pid;
//     __u32 tid;
//     __u32 ppid;
//     __u32 uid;
//     __u32 syscall_nr;
//     char comm[TASK_COMM_LEN];
//     char syscall[16];
//     __u64 args[6];
//     char filename[MAX_FILENAME_LEN];
//     char argv[MAX_ARGS][MAX_ARG_LEN];
//     __u64 cgroup_id;
//     char cgroup_name[MAX_CGROUP_NAME_LEN];  // cgroup 이름 추가
// };__attribute__((packed));


#endif // EVENT_H