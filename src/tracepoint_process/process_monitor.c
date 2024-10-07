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

    if(e->ppid != 71271)
        return 0;

    printf("Process syscall: %s (nr=%d, pid=%d, tid=%d, ppid=%d, uid=%d, comm=%s, cgroup_id=%llu, cgroup_name=%s)\n",
           e->syscall, e->syscall_nr, e->pid, e->tid, e->ppid, e->uid, e->comm, e->cgroup_id, e->cgroup_name);

    switch (e->syscall_nr) {
        case __NR_read:
        case __NR_write:
        case __NR_pread64:
        case __NR_pwrite64:
            printf("FD: %lld, Buffer: 0x%llx, Count: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_open:
        case __NR_openat:
            printf("Filename: %s, Flags: 0x%llx, Mode: 0%llo\n", e->filename, e->args[1], e->args[2]);
            break;
        case __NR_close:
            printf("FD: %lld\n", e->args[0]);
            break;
        case __NR_stat:
        case __NR_lstat:
        case __NR_fstat:
            printf("Filename: %s, Stat buf: 0x%llx\n", e->filename, e->args[1]);
            break;
        case __NR_poll:
        case __NR_select:
        case __NR_epoll_wait:
            printf("Timeout: %lld\n", e->args[4]);
            break;
        case __NR_lseek:
            printf("FD: %lld, Offset: %lld, Whence: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_mmap:
            printf("Addr: 0x%llx, Length: %lld, Prot: 0x%llx, Flags: 0x%llx, FD: %lld, Offset: %lld\n",
                   e->args[0], e->args[1], e->args[2], e->args[3], e->args[4], e->args[5]);
            break;
        case __NR_mprotect:
            printf("Addr: 0x%llx, Length: %lld, Prot: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_munmap:
            printf("Addr: 0x%llx, Length: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_brk:
            printf("Brk: 0x%llx\n", e->args[0]);
            break;
        case __NR_rt_sigaction:
            printf("Signum: %lld, Act: 0x%llx, Oldact: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_rt_sigprocmask:
            printf("How: %lld, Set: 0x%llx, Oldset: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_ioctl:
            printf("FD: %lld, Cmd: 0x%llx, Arg: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_pselect6:
        case __NR_ppoll:
            printf("Timeout: 0x%llx\n", e->args[4]);
            break;
        case __NR_nanosleep:
            printf("Req: 0x%llx, Rem: 0x%llx\n", e->args[0], e->args[1]);
            break;
        case __NR_mremap:
            printf("Old addr: 0x%llx, Old size: %lld, New size: %lld, Flags: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3]);
            break;
        case __NR_msync:
            printf("Addr: 0x%llx, Length: %lld, Flags: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_mincore:
            printf("Addr: 0x%llx, Length: %lld, Vec: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_madvise:
            printf("Addr: 0x%llx, Length: %lld, Advice: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_shmget:
            printf("Key: %lld, Size: %lld, Shmflg: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_shmat:
            printf("Shmid: %lld, Shmaddr: 0x%llx, Shmflg: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_shmctl:
            printf("Shmid: %lld, Cmd: %lld, Buf: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_dup:
        case __NR_dup2:
        case __NR_dup3:
            printf("Oldfd: %lld, Newfd: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_pause:
            printf("Process paused\n");
            break;
        case __NR_getitimer:
        case __NR_setitimer:
            printf("Which: %lld, New value: 0x%llx, Old value: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_alarm:
            printf("Seconds: %lld\n", e->args[0]);
            break;
        case __NR_getpid:
        case __NR_getppid:
            printf("Getting process ID\n");
            break;
        case __NR_socket:
            printf("Domain: %lld, Type: %lld, Protocol: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_connect:
            printf("Sockfd: %lld, Addr: 0x%llx, Addrlen: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_accept:
        case __NR_accept4:
            printf("Sockfd: %lld, Addr: 0x%llx, Addrlen: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_sendto:
        case __NR_recvfrom:
            printf("Sockfd: %lld, Buf: 0x%llx, Len: %lld, Flags: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3]);
            break;
        case __NR_sendmsg:
        case __NR_recvmsg:
            printf("Sockfd: %lld, Msg: 0x%llx, Flags: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_shutdown:
            printf("Sockfd: %lld, How: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_bind:
            printf("Sockfd: %lld, Addr: 0x%llx, Addrlen: %lld\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_listen:
            printf("Sockfd: %lld, Backlog: %lld\n", e->args[0], e->args[1]);
            break;
        case __NR_getsockname:
        case __NR_getpeername:
            printf("Sockfd: %lld, Addr: 0x%llx, Addrlen: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;
        case __NR_setsockopt:
        case __NR_getsockopt:
            printf("Sockfd: %lld, Level: %lld, Optname: %lld, Optval: 0x%llx, Optlen: 0x%llx\n",
                   e->args[0], e->args[1], e->args[2], e->args[3], e->args[4]);
            break;
        case __NR_fork:
        case __NR_vfork:
            printf("New process creation\n");
            break;

        case __NR_execve:
        case __NR_execveat:
            printf("Filename: %s\n", e->filename);
            printf("Arguments:");
            for (int i = 0; i < MAX_ARGS && e->argv[i][0] != '\0'; i++) {
                printf(" %s", e->argv[i]);
            }
            printf("\n");
            break;

        case __NR_chdir:
        case __NR_fchdir:
            printf("Changing directory to: %s\n", e->filename);
            break;

        case __NR_chmod:
        case __NR_fchmod:
        case __NR_fchmodat:
            printf("Changing file mode: %s, Mode: 0%llo\n", e->filename, e->args[1]);
            break;

        case __NR_chown:
        case __NR_fchown:
        case __NR_lchown:
        case __NR_fchownat:
            printf("Changing ownership: %s, UID: %lld, GID: %lld\n", e->filename, e->args[1], e->args[2]);
            break;

        case __NR_rename:
        case __NR_renameat:
        case __NR_renameat2:
            printf("Renaming file from: %s, to: 0x%llx\n", e->filename, e->args[1]);
            break;

        case __NR_unlink:
        case __NR_unlinkat:
            printf("Deleting file: %s\n", e->filename);
            break;

        case __NR_symlink:
        case __NR_symlinkat:
            printf("Creating symlink from: %s, to: 0x%llx\n", e->filename, e->args[1]);
            break;

        case __NR_mount:
            printf("Mounting filesystem, source: 0x%llx, target: 0x%llx, fstype: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;

        #ifdef __NR_umount
        case __NR_umount:
        #endif
        case __NR_umount2:
            printf("Unmounting filesystem: 0x%llx\n", e->args[0]);
            break;

        case __NR_ptrace:
            {
                const char *ptrace_requests[] = {
                    "PTRACE_TRACEME", "PTRACE_PEEKTEXT", "PTRACE_PEEKDATA", "PTRACE_PEEKUSER",
                    "PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_POKEUSER", "PTRACE_CONT",
                    "PTRACE_KILL", "PTRACE_SINGLESTEP"
                };
                const char *request = (e->args[0] < 10) ? ptrace_requests[e->args[0]] : "UNKNOWN";
                printf("Ptrace request: %s, pid: %lld, addr: 0x%llx, data: 0x%llx\n",
                       request, e->args[1], e->args[2], e->args[3]);
            }
            break;

        case __NR_seccomp:
            printf("Seccomp operation: %lld, flags: 0x%llx, addr: 0x%llx\n", e->args[0], e->args[1], e->args[2]);
            break;

        case __NR_prctl:
            {
                const char *prctl_options[] = {
                    "PR_SET_PDEATHSIG", "PR_GET_PDEATHSIG", "PR_GET_DUMPABLE", "PR_SET_DUMPABLE",
                    "PR_GET_UNALIGN", "PR_SET_UNALIGN", "PR_GET_KEEPCAPS", "PR_SET_KEEPCAPS",
                    "PR_GET_FPEMU", "PR_SET_FPEMU", "PR_GET_FPEXC", "PR_SET_FPEXC",
                    "PR_GET_TIMING", "PR_SET_TIMING", "PR_SET_NAME", "PR_GET_NAME"
                };
                const char *option = (e->args[0] < 16) ? prctl_options[e->args[0]] : "UNKNOWN";
                printf("Prctl option: %s, arg2: 0x%llx, arg3: 0x%llx, arg4: 0x%llx, arg5: 0x%llx\n",
                       option, e->args[1], e->args[2], e->args[3], e->args[4]);
            }
            break;

        case __NR_mknod:
        case __NR_mknodat:
            printf("Creating special file: %s, Mode: 0%llo, Dev: 0x%llx\n", e->filename, e->args[1], e->args[2]);
            break;

        case __NR_link:
        case __NR_linkat:
            printf("Creating hard link from: %s, to: 0x%llx\n", e->filename, e->args[1]);
            break;

        case __NR_waitid:
            printf("Waiting for child process (waitid)\n");
            break;
        case __NR_tkill:
            printf("Sending signal %lld to thread %lld\n", e->args[1], e->args[0]);
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