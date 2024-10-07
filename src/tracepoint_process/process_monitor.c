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
#define MAX_CONTAINERS 10
#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

static volatile bool exiting = false;

// 전역 변수로 skel 선언
static struct process_monitor_bpf *skel;

static void sig_handler(int sig)
{
    exiting = true;
}

typedef enum {
    RUNTIME_UNKNOWN,
    RUNTIME_DOCKER,
    RUNTIME_CONTAINERD,
    RUNTIME_CRIO
} ContainerRuntime;

ContainerRuntime get_runtime_from_user() {
    char input[20];
    printf("컨테이너 런타임을 입력하세요 (docker/containerd/crio): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return RUNTIME_UNKNOWN;
    }
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, "docker") == 0) return RUNTIME_DOCKER;
    else if (strcmp(input, "containerd") == 0) return RUNTIME_CONTAINERD;
    else if (strcmp(input, "crio") == 0) return RUNTIME_CRIO;
    
    return RUNTIME_UNKNOWN;
}

int get_docker_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "docker inspect -f '{{.State.Pid}}' %s", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("도커 명령어 실행 실패");
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    return atoi(output);
}

int get_containerd_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "ctr task ls | awk '$1 == \"%s\" {print $2}'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("ctr task info 명령어 실행 실패");
        return -1;
    }
    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    output[strcspn(output, "\n")] = 0;

    return atoi(output);
}

int get_crio_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "crictl inspect $(crictl ps | grep \"\\b%s\\b\" | awk '{print $1}') 2>/dev/null | grep -Po '\"pid\":\\s*\\K[0-9]+'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("crictl inspect 명령어 실행 실패");
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    output[strcspn(output, "\n")] = 0;

    return atoi(output);
}

int get_container_pid(const char* container_name) {
    ContainerRuntime runtime = get_runtime_from_user();
    
    switch(runtime) {
        case RUNTIME_DOCKER:
            printf("도커 컨테이너 PID 가져오기\n");
            return get_docker_pid(container_name);
        case RUNTIME_CONTAINERD:
            printf("containerd 컨테이너 PID 가져오기\n");
            return get_containerd_pid(container_name);
        case RUNTIME_CRIO:
            printf("CRI-O 컨테이너 PID 가져오기\n");
            return get_crio_pid(container_name);
        default:
            fprintf(stderr, "알 수 없거나 지원되지 않는 컨테이너 런타임\n");
            return -1;
    }
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
        strncpy(value, syscall_list[i].name, sizeof(value) - 1);  // 문자열 복사 및 null 종료 보장
        bpf_map__update_elem(skel->maps.syscall_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    __u32 key = e->ppid;
    __u32 value;

    // container_pids 맵에서 현재 프로세스의 PPID를 찾습니다.
    if (bpf_map__lookup_elem(skel->maps.container_pids, &key, sizeof(key), &value, sizeof(value), 0) == 0) {
        // PPID가 맵에 있으면 로깅을 수행합니다.
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

            case __NR_waitid:
                printf("Waiting for child process (waitid)\n");
                break;
            case __NR_tkill:
                printf("Sending signal %lld to thread %lld\n", e->args[1], e->args[0]);
                break;
            case __NR_tgkill:
                printf("Sending signal %lld to thread %lld in thread group %lld\n", e->args[2], e->args[1], e->args[0]);
                break;
            case __NR_setpgid:
                printf("Setting process group ID: pid %lld, pgid %lld\n", e->args[0], e->args[1]);
                break;
            case __NR_setsid:
                printf("Creating new session\n");
                break;
            case __NR_setuid:
            case __NR_setgid:
            case __NR_setreuid:
            case __NR_setregid:
            case __NR_setresuid:
            case __NR_setresgid:
                printf("Changing process UID/GID\n");
                break;
            case __NR_setgroups:
                printf("Setting supplementary group IDs\n");
                break;
            case __NR_prctl:
                printf("Process control operation: %lld\n", e->args[0]);
                break;
            case __NR_capset:
                printf("Setting process capabilities\n");
                break;
            case __NR_setpriority:
                printf("Setting process priority: %lld for process %lld\n", e->args[2], e->args[1]);
                break;
            case __NR_sched_setscheduler:
                printf("Setting scheduling policy and parameters for process %lld\n", e->args[0]);
                break;
            case __NR_sched_setparam:
                printf("Setting scheduling parameters for process %lld\n", e->args[0]);
                break;
            case __NR_sched_setaffinity:
                printf("Setting CPU affinity for process %lld\n", e->args[0]);
                break;
            case __NR_sched_yield:
                printf("Yielding processor\n");
                break;
        }
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

    // 컨테이너 이름 입력 받기
    char container_name[256];
    printf("모니터링할 컨테이너 이름을 입력하세요: ");
    if (fgets(container_name, sizeof(container_name), stdin) == NULL) {
        fprintf(stderr, "컨테이너 이름 입력 실패\n");
        goto cleanup;
    }
    container_name[strcspn(container_name, "\n")] = 0;  // 개행 문자 제거

    // 컨테이너 PID 가져오기
    int container_pid = get_container_pid(container_name);
    if (container_pid < 0) {
        fprintf(stderr, "컨테이너 PID를 가져오는데 실패했습니다\n");
        goto cleanup;
    }

    printf("모니터링 중인 컨테이너 PID: %d\n", container_pid);

    // 컨테이너 PID를 BPF 맵에 추가
    __u32 key = container_pid;
    __u32 value = 1;
    err = bpf_map__update_elem(skel->maps.container_pids, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    if (err) {
        fprintf(stderr, "컨테이너 PID를 맵에 추가하는데 실패했습니다: %d\n", err);
        goto cleanup;
    }

    // 컨테이너의 자식 프로세스들도 모니터링하기 위해 0을 키로 추가
    key = 0;
    err = bpf_map__update_elem(skel->maps.container_pids, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    if (err) {
        fprintf(stderr, "0 PID를 맵에 추가하는데 실패했습니다: %d\n", err);
        goto cleanup;
    }

    init_syscall_map(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 메인 루프
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);  // 100ms 타임아웃으로 폴링
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "링 버퍼 폴링 중 오류 발생: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}