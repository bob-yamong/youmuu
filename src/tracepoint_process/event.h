#ifndef EVENT_H
#define EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS 3
#define MAX_ARG_LEN 128

struct event {
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
} __attribute__((packed));

#endif // EVENT_H
