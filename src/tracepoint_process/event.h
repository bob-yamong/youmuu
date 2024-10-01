#ifndef EVENT_H
#define EVENT_H

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 uid;
    __u32 syscall_nr;
    char comm[TASK_COMM_LEN];
    char syscall[16];
} __attribute__((packed));

#endif // EVENT_H
