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
        // 프로세스 관련
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_wait4, "wait4" },
        { __NR_kill, "kill" },
        { __NR_ptrace, "ptrace" },

        // 파일 시스템 관련
        { __NR_open, "open" },
        { __NR_openat, "openat" },
        { __NR_close, "close" },
        { __NR_read, "read" },
        { __NR_write, "write" },
        { __NR_lseek, "lseek" },
        { __NR_unlink, "unlink" },
        { __NR_rename, "rename" },
        { __NR_mkdir, "mkdir" },
        { __NR_rmdir, "rmdir" },
        { __NR_chdir, "chdir" },
        { __NR_chmod, "chmod" },
        { __NR_chown, "chown" },
        { __NR_mount, "mount" },
        { __NR_umount2, "umount2" },

        // 네트워크 관련
        { __NR_socket, "socket" },
        { __NR_connect, "connect" },
        { __NR_accept, "accept" },
        { __NR_bind, "bind" },
        { __NR_listen, "listen" },
        { __NR_sendto, "sendto" },
        { __NR_recvfrom, "recvfrom" },
        { __NR_setsockopt, "setsockopt" },
        { __NR_getsockopt, "getsockopt" },
    };

    int map_fd = bpf_map__fd(skel->maps.syscall_map);

    for (int i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
        int key = syscall_list[i].nr;
        const char *value = syscall_list[i].name;
        bpf_map_update_elem(map_fd, &key, value, BPF_ANY);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Process syscall: %s (nr=%d, pid=%d, tid=%d, ppid=%d, uid=%d, comm=%s, cgroup_id=%llu, cgroup_name=%s)\n",
           e->syscall, e->syscall_nr, e->pid, e->tid, e->ppid, e->uid, e->comm, e->cgroup_id, e->cgroup_name);

    switch (e->syscall_nr) {
        // 프로세스 관련
        case __NR_fork:
        case __NR_vfork:
        case __NR_clone:
            printf("New process creation\n");
            break;
        case __NR_execve:
            printf("Executing new program: %s\n", e->filename);
            for (int i = 0; i < MAX_ARGS && e->argv[i][0] != '\0'; i++) {
                printf("Arg %d: %s\n", i, e->argv[i]);
            }
            break;
        case __NR_exit:
        case __NR_exit_group:
            printf("Process exit\n");
            break;
        case __NR_wait4:
            printf("Waiting for child process\n");
            break;
        case __NR_kill:
            printf("Sending signal %lld to process %lld\n", e->args[1], e->args[0]);
            break;
        case __NR_ptrace:
            printf("Ptrace call with request %lld\n", e->args[0]);
            break;

        // 파일 시스템 관련
        case __NR_open:
        case __NR_openat:
            printf("Opening file: %s\n", e->filename);
            break;
        case __NR_close:
            printf("Closing file descriptor: %lld\n", e->args[0]);
            break;
        case __NR_read:
        case __NR_write:
            printf("%s operation on fd %lld, %lld bytes\n", 
                   e->syscall_nr == __NR_read ? "Read" : "Write", e->args[0], e->args[2]);
            break;
        case __NR_unlink:
            printf("Deleting file: %s\n", e->filename);
            break;
        case __NR_rename:
            printf("Renaming file\n");
            break;
        case __NR_mkdir:
            printf("Creating directory: %s\n", e->filename);
            break;
        case __NR_rmdir:
            printf("Removing directory: %s\n", e->filename);
            break;
        case __NR_chdir:
            printf("Changing directory to: %s\n", e->filename);
            break;
        case __NR_chmod:
            printf("Changing file mode: %s\n", e->filename);
            break;
        case __NR_chown:
            printf("Changing file ownership: %s\n", e->filename);
            break;
        case __NR_mount:
            printf("Mounting filesystem\n");
            break;
        case __NR_umount2:
            printf("Unmounting filesystem\n");
            break;

        // 네트워크 관련
        case __NR_socket:
            printf("Creating socket: domain %lld, type %lld, protocol %lld\n", 
                   e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_connect:
            printf("Connecting to socket\n");
            break;
        case __NR_accept:
            printf("Accepting connection on socket\n");
            break;
        case __NR_bind:
            printf("Binding socket\n");
            break;
        case __NR_listen:
            printf("Listening on socket\n");
            break;
        case __NR_sendto:
        case __NR_recvfrom:
            printf("%s on socket %lld, %lld bytes\n", 
                   e->syscall_nr == __NR_sendto ? "Sending" : "Receiving", e->args[0], e->args[2]);
            break;
        case __NR_setsockopt:
        case __NR_getsockopt:
            printf("%s socket option\n", e->syscall_nr == __NR_setsockopt ? "Setting" : "Getting");
            break;
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