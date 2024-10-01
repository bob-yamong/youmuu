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
#include "network.skel.h"

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
    {"sys_enter_socket", 0},
    {"sys_exit_socket", 1},
    {"sys_enter_socketpair", 2},
    {"sys_exit_socketpair", 3},
    {"sys_enter_setsockopt", 4},
    {"sys_exit_setsockopt", 5},
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

void get_user_input(struct network_bpf *skel, __u64 ns_id, __u32 event_id) {
    char action_str[10];
    __u32 action;
    int err;

    printf("Enter action to block or allow (e.g., block, allow, logging): ");
    if (fgets(action_str, sizeof(action_str), stdin) == NULL) {
        return;
    }
    action_str[strcspn(action_str, "\n")] = 0;

    if (strcmp(action_str, "allow") == 0) action = ALLOW;
    else if (strcmp(action_str, "block") == 0) action = BLOCK;
    else if (strcmp(action_str, "logging") == 0) action = LOGGING;

    struct event_key key = {
        .ns_id = ns_id,
        .event_id = event_id
    };
    err = bpf_map__update_elem(skel->maps.event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map: %d\n", err);
        return;
    }
    printf("Updated map with action: %d, namespace_id: %llu, evnet_id: %d\n", action, ns_id, event_id);
}

int main(int argc, char **argv) {
    struct network_bpf *skel;
    __u64 ns_id;
    int err;

    skel = network_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = network_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = network_bpf__attach(skel);
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
    network_bpf__destroy(skel);
    return err != 0;
}