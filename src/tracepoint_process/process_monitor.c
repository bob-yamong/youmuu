// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_SYSCALL_ENTRIES 256

static volatile bool exiting = false;

void handle_signal(int sig)
{
    exiting = true;
}

void init_syscall_map(struct process_monitor_bpf *skel)
{
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_kill, "kill" },
        { __NR_tkill, "tkill" },
        { __NR_tgkill, "tgkill" },
        { __NR_ptrace, "ptrace" },
        { __NR_setpgid, "setpgid" },
        { __NR_setsid, "setsid" },
        { __NR_setuid, "setuid" },
        { __NR_setgid, "setgid" },
        { __NR_setreuid, "setreuid" },
        { __NR_setregid, "setregid" },
        { __NR_setresuid, "setresuid" },
        { __NR_setresgid, "setresgid" },
        { __NR_setgroups, "setgroups" },
        { __NR_prctl, "prctl" },
        { __NR_capset, "capset" },
        { __NR_setpriority, "setpriority" },
        { __NR_sched_setscheduler, "sched_setscheduler" },
        { __NR_sched_setparam, "sched_setparam" },
        { __NR_sched_setaffinity, "sched_setaffinity" },
        { __NR_sched_yield, "sched_yield" },
    };

    int size = sizeof(syscall_list) / sizeof(syscall_list[0]);
    for (int i = 0; i < size; i++) {
        int nr = syscall_list[i].nr;
        const char *name = syscall_list[i].name;
        char value[16] = {0};
        strncpy(value, name, sizeof(value) - 1);
        int err = bpf_map__update_elem(skel->maps.syscall_map, &nr, sizeof(nr), value, sizeof(value), 0);
        if (err) {
            fprintf(stderr, "Failed to update syscall map for %s: %d\n", name, err);
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    // 88919 프로세스의 시스템 콜만 출력
    if(e->ppid != 88919)
        return 0;   
    printf("Process syscall: %s (nr=%d, pid=%d, tid=%d, ppid=%d, uid=%d, comm=%s)\n",
           e->syscall, e->syscall_nr, e->pid, e->tid, e->ppid, e->uid, e->comm);
    
    // 시스템 콜별로 인자 파싱 및 출력
    switch (e->syscall_nr) {
        case __NR_clone:
            printf("Clone flags: 0x%llx, Child stack: 0x%llx, Parent tidptr: 0x%llx, Child tidptr: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3]);
            break;
        case __NR_execve:
            printf("Filename: %s\n", e->filename);
            printf("Arguments:");
            for (int i = 0; i < MAX_ARGS && e->argv[i][0] != '\0'; i++) {
                printf(" %s", e->argv[i]);
            }
            printf("\n");
            break;
        case __NR_exit:
        case __NR_exit_group:
            printf("Exit code: %lld\n", e->args[0]);
            break;
        case __NR_wait4: {
            int status;
            if (e->args[1] != 0) {
                if (read_process_memory(e->pid, (void *)e->args[1], &status, sizeof(status)) == 0) {
                    printf("PID: %lld, Status: 0x%x, Options: 0x%llx, Rusage ptr: 0x%llx\n",
                           e->args[0], status, e->args[2], e->args[3]);
                } else {
                    printf("PID: %lld, Status ptr: 0x%llx (failed to read), Options: 0x%llx, Rusage ptr: 0x%llx\n",
                           e->args[0], e->args[1], e->args[2], e->args[3]);
                }
            } else {
                printf("PID: %lld, Status ptr: NULL, Options: 0x%llx, Rusage ptr: 0x%llx\n",
                       e->args[0], e->args[2], e->args[3]);
            }
            break;
        }
        case __NR_kill:
        case __NR_tkill:
        case __NR_tgkill:
            printf("Target PID: %lld, Signal: %s (%lld)\n", e->args[0], strsignal(e->args[1]), e->args[1]);
            break;
        case __NR_ptrace:
            printf("Request: %lld, Target PID: %lld, Addr: 0x%llx, Data: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3]);
            break;
        case __NR_setpgid:
            printf("PID: %lld, PGID: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_setsid:
            printf("New session created\n");
            break;
        case __NR_setuid:
        case __NR_setgid:
            printf("New ID: %lld\n", e->args[0]);
            break;
        case __NR_setreuid:
        case __NR_setregid:
            printf("Real ID: %lld, Effective ID: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_setresuid:
        case __NR_setresgid:
            printf("Real ID: %lld, Effective ID: %lld, Saved ID: %lld\n",
                   e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_setgroups:
            printf("Size: %lld, List ptr: 0x%llx\n", e->args[0], e->args[1]);
            break;
        case __NR_prctl:
            printf("Option: %lld, Arg2: 0x%llx, Arg3: 0x%llx, Arg4: 0x%llx, Arg5: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3], e->args[4]);
            break;
        case __NR_capset:
            printf("Header ptr: 0x%llx, Data ptr: 0x%llx\n", e->args[0], e->args[1]);
            break;
        case __NR_setpriority:
            printf("Which: %lld, Who: %lld, Prio: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_sched_setscheduler:
            printf("PID: %lld, Policy: %lld, Param ptr: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_sched_setparam:
            printf("PID: %lld, Param ptr: 0x%llx\n", e->args[0], e->args[1]);
            break;
        case __NR_sched_setaffinity:
            printf("PID: %lld, CPU set size: %lld, Mask ptr: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_sched_yield:
            printf("Process yielding CPU\n");
            break;
        default:
            printf("Args: 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3], e->args[4], e->args[5]);
    }
    
    return 0;
}

// 프로세스 메모리 읽기 함수 추가
int read_process_memory(pid_t pid, void *addr, void *buf, size_t len)
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    
    ssize_t bytes_read = pread(fd, buf, len, (off_t)addr);
    close(fd);
    
    return (bytes_read == len) ? 0 : -1;
}

void set_current_pid(struct process_monitor_bpf *skel)
{
    __u32 key = 0;
    __u32 pid = getpid();
    int err = bpf_map__update_elem(skel->maps.current_pid, &key, sizeof(key), &pid, sizeof(pid), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update current_pid map: %d\n", err);
    }
}

int main(int argc, char **argv)
{
    struct process_monitor_bpf *skel;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    skel = process_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton\n");
        return 1;
    }

    set_current_pid(skel);  // 현재 PID 설정

    init_syscall_map(skel);

    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF program: %d\n", err);
        process_monitor_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Process monitoring started. Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        // 주기적으로 exiting 플래그를 확인
        if (exiting) {
            break;
        }
    }

    printf("Cleaning up...\n");

cleanup:
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}