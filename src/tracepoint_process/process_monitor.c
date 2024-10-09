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
#include <curl/curl.h>
#include <json-c/json.h>

#define MAX_SYSCALL_ENTRIES 256
#define MAX_CONTAINERS 100  // MAX_CONTAINERS를 100으로 변경
#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

// string 구조체 정의 추가
struct string {
    char *ptr;
    size_t len;
};

static volatile bool exiting = false;

// 전역 변수로 skel 선언
static struct process_monitor_bpf *skel;

static void sig_handler(int sig)
{
    exiting = true;
}

// 제거 또는 주석 처리
// int get_docker_pid(const char* container_name)
// int get_containerd_pid(const char* container_name)
// int get_crio_pid(const char* container_name)
// int get_container_pid(const char* container_name)
// ContainerRuntime get_runtime_from_user()

// typedef enum {
//     RUNTIME_UNKNOWN,
//     RUNTIME_DOCKER,
//     RUNTIME_CONTAINERD,
//     RUNTIME_CRIO
// } ContainerRuntime;

// 제거 (get_container_pids 함수에서 사용됨)
#define DOCKER_SOCKET "/var/run/docker.sock"

struct container_info {
    char id[64];
    int pid;
};

struct container_info containers[MAX_CONTAINERS];
int container_count = 0;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct string *mem = (struct string *)userp;

    char *ptr = realloc(mem->ptr, mem->len + realsize + 1);
    if (!ptr) {
        printf("메모리 할당 실패\n");
        return 0;
    }

    mem->ptr = ptr;
    memcpy(&(mem->ptr[mem->len]), contents, realsize);
    mem->len += realsize;
    mem->ptr[mem->len] = 0;

    return realsize;
}

int get_container_pids() {
    CURL *curl;
    CURLcode res;
    struct string s;
    s.len = 0;
    s.ptr = malloc(1);
    s.ptr[0] = '\0';

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, DOCKER_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/containers/json");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&s);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            json_object *jobj = json_tokener_parse(s.ptr);
            if (jobj) {
                int array_len = json_object_array_length(jobj);
                for (int i = 0; i < array_len && i < MAX_CONTAINERS; i++) {
                    json_object *container = json_object_array_get_idx(jobj, i);
                    json_object *id;
                    if (json_object_object_get_ex(container, "Id", &id)) {
                        strncpy(containers[i].id, json_object_get_string(id), sizeof(containers[i].id) - 1);
                        containers[i].id[sizeof(containers[i].id) - 1] = '\0';

                        char inspect_url[256];
                        snprintf(inspect_url, sizeof(inspect_url), "http://localhost/containers/%s/json", containers[i].id);
                        
                        struct string inspect_s;
                        inspect_s.len = 0;
                        inspect_s.ptr = malloc(1);
                        inspect_s.ptr[0] = '\0';

                        curl_easy_setopt(curl, CURLOPT_URL, inspect_url);
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&inspect_s);
                        res = curl_easy_perform(curl);
                        if (res == CURLE_OK) {
                            json_object *inspect_jobj = json_tokener_parse(inspect_s.ptr);
                            if (inspect_jobj) {
                                json_object *state, *pid;
                                if (json_object_object_get_ex(inspect_jobj, "State", &state) &&
                                    json_object_object_get_ex(state, "Pid", &pid)) {
                                    containers[i].pid = json_object_get_int(pid);
                                    container_count++;
                                }
                                json_object_put(inspect_jobj);
                            }
                        }
                        free(inspect_s.ptr);
                    }
                }
                json_object_put(jobj);
            }
        }
        curl_easy_cleanup(curl);
    }
    free(s.ptr);

    return container_count;
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
    __u64 key = e->cgroup_id;
    __u64 value;

    // container_pids 맵에서 현재 프로세스의 PPID를 찾습니다.
    if (bpf_map__lookup_elem(skel->maps.container_cgroup_id, &key, sizeof(key), &value, sizeof(value), 0) == 0 ) {
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
                printf("Opening file: %lld\n", e->args[0]);
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

// 제거 또는 주석 처리
// int read_process_memory(pid_t pid, void *addr, void *buf, size_t len)
// {
//     char path[32];
//     snprintf(path, sizeof(path), "/proc/%d/mem", pid);
//     
//     int fd = open(path, O_RDONLY);
//     if (fd == -1) return -1;
//     
//     ssize_t bytes_read = pread(fd, buf, len, (off_t)addr);
//     close(fd);
//     
//     return (bytes_read == len) ? 0 : -1;
// }

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
        __u32 key = containers[i].pid;
        __u32 value = 1;
        err = bpf_map__update_elem(skel->maps.container_pids, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
        if (err) {
            fprintf(stderr, "컨테이너 PID %d를 맵에 추가하는데 실패했습니다: %d\n", containers[i].pid, err);
        } else {
            printf("컨테이너 ID: %s, PID: %d를 모니터링 중\n", containers[i].id, containers[i].pid);
        }
    }

    // 주석 처리 (사용되지 않음)
    // // 컨테이너의 자식 프로세스들도 모니터링하기 위해 0을 키로 추가
    // __u32 key = 0;
    // __u32 value = 1;
    // err = bpf_map__update_elem(skel->maps.container_pids, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    // if (err) {
    //     fprintf(stderr, "0 PID를 맵에 추가하는데 실패했습니다: %d\n", err);
    //     goto cleanup;
    // }

    init_syscall_map(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 메인 루프
    while (!exiting) {
        err = ring_buffer__poll(rb, 50);  // 100ms 타임아웃으로 폴링
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