// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "event.h" 
#include "container_info.h"


static bool exiting = false;

// 전역 변수로 skel 선언
struct process_monitor_bpf *skel;

static void sig_handler(int sig)
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

    for (int i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
        int key = syscall_list[i].nr;
        char value[16] = {0};  // 16바이트 버퍼 생성
        strncpy(value, syscall_list[i].name, sizeof(value) - 1); 
        bpf_map__update_elem(skel->maps.syscall_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    __u64 key = e->cgroup_id;
    __u64 value = 1;

    if (bpf_map__lookup_elem(skel->maps.container_cgroup_id, &key, sizeof(key), &value, sizeof(value), 0) == 0) {
        printf("Process syscall: %s (nr=%d, pid=%d, tid=%d, ppid=%d, uid=%d, comm=%s, cgroup_id=%llu, cgroup_name=%s)\n",
               e->syscall,  e->syscall_nr, e->pid, e->tid, e->ppid, e->uid, e->comm, e->cgroup_id, e->cgroup_name);

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
            case __NR_waitid:
                printf("Waiting for child process\n");
                break;
            case __NR_kill:
            case __NR_tkill:
            case __NR_tgkill:
                printf("Sending signal %lld to process/thread\n", e->args[1]);
                break;
            case __NR_ptrace:
                printf("Ptrace call with request %lld\n", e->args[0]);
                break;

            // 파일 시스템 관련
            case __NR_open:
            case __NR_openat:
            case __NR_unlink:
            case __NR_unlinkat:
            case __NR_mkdir:
            case __NR_mkdirat:
            case __NR_rmdir:
            case __NR_renameat:
            case __NR_renameat2:
            case __NR_symlink:
            case __NR_symlinkat:
            case __NR_link:
            case __NR_linkat:
            case __NR_chmod:
            case __NR_fchmodat:
            case __NR_chown:
            case __NR_lchown:
            case __NR_fchownat:
            case __NR_access:
            case __NR_faccessat:
            case __NR_stat:
            case __NR_lstat:
            case __NR_newfstatat:
            case __NR_truncate:
            case __NR_readlink:
            case __NR_readlinkat:
                if (e->filename[0] != '\0') {
                    printf("File operation: %s on file: %s\n", e->syscall, e->filename);
                }
                break;
            case __NR_close:
                printf("Closing file descriptor: %lld\n", e->args[0]);
                break;
            case __NR_read:
            case __NR_write:
                printf("%s operation on fd %lld, %lld bytes\n", 
                       e->syscall_nr == __NR_read ? "Read" : "Write", e->args[0], e->args[2]);
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

            // 프로세스 제어 관련
            case __NR_setpgid:
            case __NR_setsid:
            case __NR_setuid:
            case __NR_setgid:
            case __NR_setreuid:
            case __NR_setregid:
            case __NR_setresuid:
            case __NR_setresgid:
            case __NR_setgroups:
            case __NR_capset:
                printf("Changing process attributes: %s\n", e->syscall);
                break;
            case __NR_prctl:
                printf("Process control operation: %lld\n", e->args[0]);
                break;
            case __NR_setpriority:
            case __NR_sched_setscheduler:
            case __NR_sched_setparam:
            case __NR_sched_setaffinity:
                printf("Changing process scheduling: %s\n", e->syscall);
                break;
            case __NR_sched_yield:
                printf("Yielding processor\n");
                break;

            default:
                printf("Other system call: %s\n", e->syscall);
                break;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int err;

    // Ctrl-C 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // BPF 애플리케이션 로드 및 검증
    skel = process_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF 스켈레톤을 열고 로드하는데 실패했습니다\n");
        return 1;
    }

    // BPF 프로그램 연결
    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "BPF 스켈레톤을 연결하는데 실패했습니다: %d\n", err);
        goto cleanup;
    }

    printf("성공적으로 BPF 프로그램을 시작했습니다! 프로세스 모니터링을 시작합니다...\n");

    printf("컨테이너 PID 자동 감지 중...\n");
    int detected_containers = get_container_pids();
    if (detected_containers <= 0) {
        fprintf(stderr, "실행 중인 컨테이너를 찾을 수 없습니다.\n");
        goto cleanup;
    }
    printf("%d개의 컨테이너를 감지했습니다.\n", detected_containers);

    for (int i = 0; i < detected_containers; i++) {
        __u32 key_pid = containers[i].pid;
        __u32 value_pid = 1;
        __u64 key_inode = get_container_inode(containers[i].id);
        __u64 value_inode = 1;

        int err_pid = bpf_map__update_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), &value_pid, sizeof(value_pid), BPF_ANY);
        int err_inode = bpf_map__update_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), &value_inode, sizeof(value_inode), BPF_ANY);
        if (err_pid || err_inode) {
            fprintf(stderr, "컨테이너 PID %d를 맵에 추가하는데 실패했습니다: %d\n", containers[i].pid, err_pid);
            fprintf(stderr, "컨테이너 inode %llu를 맵에 추가하는데 실패했습니다: %d\n", key_inode, err_inode);
        } else {
            // printf("컨테이너 ID: %s, PID: %d를 모니터링 중\n", containers[i].id, containers[i].pid);
            printf("컨테이너 ID: %s, PID: %d, inode: %llu를 모니터링 중\n", containers[i].id, containers[i].pid, key_inode);
        }
    }


    init_syscall_map(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }


    // 메인 루프
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
    }

cleanup:
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}