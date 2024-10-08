#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "tracepoint.skel.h"

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256
#define MAX_PATH 256
#define ALLOW 0
#define BLOCK 1
#define LOGGING 2

struct event_key {
    __u64 ns_id;
    __u32 event_id;
    char argument[256];
};

struct EventMapping {
    const char *name;
    __u32 id;
};

static const struct EventMapping event_mappings[] = {
    {"sys_enter_socket", 1},
    {"sys_exit_socket", 2},
    {"sys_enter_socketpair", 3},
    {"sys_exit_socketpair", 4},
    {"sys_enter_setsockopt", 5},
    {"sys_exit_setsockopt", 6},
    {"sys_enter_getsockopt", 7},
    {"sys_exit_getsockopt", 8},
    {"sys_enter_getsockname", 9},
    {"sys_exit_getsockname", 10},
    {"sys_enter_getpeername", 11},
    {"sys_exit_getpeername", 12},
    {"sys_enter_bind", 13},
    {"sys_exit_bind", 14},
    {"sys_enter_listen", 15},
    {"sys_exit_listen", 16},
    {"sys_enter_accept", 17},
    {"sys_exit_accept", 18},
    {"sys_enter_accept4", 19},
    {"sys_exit_accept4", 20},
    {"sys_enter_connect", 21},
    {"sys_exit_connect", 22},
    {"sys_enter_shutdown", 23},
    {"sys_exit_shutdown", 24},
    {"sys_enter_recvfrom", 25},
    {"sys_exit_recvfrom", 26},
    {"sys_enter_recvmsg", 27},
    {"sys_exit_recvmsg", 28},
    {"sys_enter_recvmmsg", 29},
    {"sys_exit_recvmmsg", 30},
    {"sys_enter_sendto", 31},
    {"sys_exit_sendto", 32},
    {"sys_enter_sendmsg", 33},
    {"sys_exit_sendmsg", 34},
    {"sys_enter_sendmmsg", 35},
    {"sys_exit_sendmmsg", 36},
    {"sys_enter_sethostname", 37},
    {"sys_exit_sethostname", 38},
    {"sys_enter_setdomainname", 39},
    {"sys_exit_setdomianname", 40},
    {"sys_enter_close", 41},
    {"sys_exit_close", 42},
    {"sys_enter_creat", 43},
    {"sys_exit_creat", 44},
    {"sys_enter_open", 45},
    {"sys_exit_open", 46},
    {"sys_enter_openat", 47},
    {"sys_exit_openat", 48},
    {"sys_enter_openat2", 49},
    {"sys_exit_openat2", 50},
    {"sys_enter_name_to_handle_at", 51},
    {"sys_exit_name_to_handle_at", 52},
    {"sys_enter_open_by_handle_at", 53},
    {"sys_exit_open_by_handle_at", 54},
    {"sys_enter_memfd_create", 55},
    {"sys_exit_memfd_create", 56},
    // 메모리 관련 이벤트는 파일 시스템과 관련이 없을수도 있음, 검토 필요, 
    // 메모리 보호를 변경하는 방식으로 공격을 시작하거나 공격 도중 사용하는 경우에는 메모리 관련 모니터링이 필요할 수 있지만, 
    // 이는 메모리 내 데이터 보호나 악성 코드 실행 방지와 더 관련이 있음. 아마도 프로세스 모니터링 제어에서 참고할 수도? -> 실제로 프로세스 모니터링 제어에서 참고함
    {"sys_enter_mmap", 57},
    {"sys_exit_mmap", 58},
    {"sys_enter_munmap", 59},
    {"sys_exit_munmap", 60},
    {"sys_enter_mprotect", 61},
    {"sys_exit_mprotect", 62},
    {"sys_enter_pkey_mprotect", 63},
    {"sys_exit_pkey_mprotect", 64},
    // 여기까지 
    {"sys_enter_mknod", 65},
    {"sys_exit_mknod", 66},
    {"sys_enter_mknodat", 67},
    {"sys_exit_mknodat", 68},
    {"sys_enter_rename", 69},
    {"sys_exit_rename", 70},
    {"sys_enter_renameat", 71},
    {"sys_exit_renameat", 72},
    {"sys_enter_renameat2", 73},
    {"sys_exit_renameat2", 74},
    {"sys_enter_truncate", 75},
    {"sys_exit_truncate", 76},
    {"sys_enter_ftruncate", 77},
    {"sys_exit_ftruncate", 78},
    {"sys_enter_fallocate", 79},
    {"sys_exit_fallocate", 80},
    {"sys_enter_mkdir", 81},
    {"sys_exit_mkdir", 82},
    {"sys_enter_mkdirat", 83},
    {"sys_exit_mkdirat", 84},
    {"sys_enter_rmdir", 85},
    {"sys_exit_rmdir", 86},
    {"sys_enter_getcwd", 87},
    {"sys_exit_getcwd", 88},
    {"sys_enter_chdir", 89},
    {"sys_exit_chdir", 90},
    {"sys_enter_fchdir", 91},
    {"sys_exit_fchdir", 92},
    {"sys_enter_chroot", 93},
    {"sys_exit_chroot", 94},
    {"sys_enter_getdents", 95},
    {"sys_exit_getdents", 96},
    {"sys_enter_getdents64", 97},
    {"sys_exit_getdents64", 98},
    {"sys_enter_link", 99},
    {"sys_exit_link", 100},
    {"sys_enter_linkat", 101},
    {"sys_exit_linkat", 102},
    {"sys_enter_symlink", 103},
    {"sys_exit_symlink", 104},
    {"sys_enter_symlinkat", 105},
    {"sys_exit_symlinkat", 106},
    {"sys_enter_unlink", 107},
    {"sys_exit_unlink", 108},
    {"sys_enter_unlinkat", 109},
    {"sys_exit_unlinkat", 110},
    {"sys_enter_readlink", 111},
    {"sys_exit_readlink", 112},
    {"sys_enter_readlinkat", 113},
    {"sys_exit_readlinkat", 114},
    // 새로운 이벤트를 여기에 추가
    {NULL, 0}  // 배열의 끝을 나타내는 센티널
};

typedef enum {
    RUNTIME_UNKNOWN,
    RUNTIME_DOCKER,
    RUNTIME_CONTAINERD,
    RUNTIME_CRIO
} ContainerRuntime;

ContainerRuntime get_runtime_from_user() {
    char input[20];
    printf("Enter container runtime (docker/containerd/crio): ");
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
        perror("Failed to run docker command");
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    return atoi(output);
}

// 여러개 가능, 현재는 name으로 찾지만 label, namespace 구현 필요
int get_containerd_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "ctr task ls | awk '$1 == \"%s\" {print $2}'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run ctr task info command");
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

// 여러개 가능, 현재는 name인데 사실 pod임 추가로 label, namespace 구현 필요
int get_crio_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "crictl inspect $(crictl ps | grep \"\\b%s\\b\" | awk '{print $1}') 2>/dev/null | grep -Po '\"pid\":\\s*\\K[0-9]+'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run crictl inspect command");
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
            printf("docker\n");
            return get_docker_pid(container_name);
        case RUNTIME_CONTAINERD:
            printf("containerd\n");
            return get_containerd_pid(container_name);
        case RUNTIME_CRIO:
            printf("cri-o\n");
            return get_crio_pid(container_name);
        default:
            fprintf(stderr, "Unknown or unsupported container runtime\n");
            return -1;
    }
}

__u64 get_namespace_id(int container_pid) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", container_pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open namespace file");
        return 1;
    }

    char link_target[MAX_PATH];
    ssize_t len = readlink(path, link_target, sizeof(link_target)-1);
    if (len < 0) {
        perror("Failed to read link");
        close(fd);
        return 1;
    }
    link_target[len] = '\0';

    unsigned int ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1) {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 1;
    }

    printf("PID namespace ID for PID %d: %u\n", container_pid, ns_id);

    close(fd);
    return ns_id;
}

__u32 get_event_id(const char *event_str) {
    for (int i = 0; event_mappings[i].name != NULL; i++) {
        if (strcmp(event_str, event_mappings[i].name) == 0) {
            return event_mappings[i].id;
        }
    }
    return (uint32_t)-1;  // 알 수 없는 이벤트
}

void get_user_input(struct tracepoint_bpf *skel, __u64 ns_id, __u32 event_id) {
    char action_str[10];
    __u32 action = LOGGING;
    int err;

    printf("Enter action (allow/block/logging, default is logging): ");
    if (fgets(action_str, sizeof(action_str), stdin) == NULL) {
        return;
    }
    action_str[strcspn(action_str, "\n")] = 0;

    if (strcmp(action_str, "allow") == 0) action = ALLOW;
    else if (strcmp(action_str, "block") == 0) action = BLOCK;

    struct event_key key = {
        .ns_id = ns_id,
        .event_id = event_id
    };
    err = bpf_map__update_elem(skel->maps.event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map: %d\n", err);
        return;
    }
    printf("Updated map with action: %d, namespace_id: %llu, event_id: %d\n", action, ns_id, event_id);
}

int main(int argc, char **argv) {
    struct tracepoint_bpf *skel;
    __u64 ns_id;
    int err;

    skel = tracepoint_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = tracepoint_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = tracepoint_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    ContainerRuntime runtime = get_runtime_from_user();
    
container_name:
    char container_str[256];
    __u32 pid;

    printf("Enter container name to restrict (or 'quit' to exit): ");
    if (fgets(container_str, sizeof(container_str), stdin) == NULL) {
        return 1;
    }
    container_str[strcspn(container_str, "\n")] = 0;
    if (strcmp(container_str, "quit") == 0) {
            return 0;
    }
    
    switch(runtime) {
        case RUNTIME_DOCKER:
            pid = get_docker_pid(container_str);
            break;
        case RUNTIME_CONTAINERD:
            pid =  get_containerd_pid(container_str);
            break;
        case RUNTIME_CRIO:
            pid = get_crio_pid(container_str);
            break;
        default:
            fprintf(stderr, "Unknown or unsupported container runtime\n");
            return -1;
    }
    ns_id = get_namespace_id(pid);

    while (1) {
        char event_str[256];
        
        printf("Enter event (e.g., sys_enter_socket, sys_exit_socket, or 'quit' to exit): ");
        if (fgets(event_str, sizeof(event_str), stdin) == NULL) {
            break;
        }
        event_str[strcspn(event_str, "\n")] = 0;
        if (strcmp(event_str, "quit") == 0) goto container_name;

        __u32 event_id = get_event_id(event_str);
        if (event_id == (uint32_t)-1) {
            fprintf(stderr, "Unknown event\n");
            continue;
        }
        get_user_input(skel, ns_id, event_id);
    }
cleanup:
    tracepoint_bpf__destroy(skel);
    return err != 0;
}