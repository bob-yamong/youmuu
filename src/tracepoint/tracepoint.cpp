#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <asm/unistd_64.h>
#include <bpf/libbpf.h>
#include "tracepoint.skel.h"
#include "structs.h"
#include "handler.h"

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256
#define MAX_PATH 256
#define MAX_EVENTS 4096
#define ALLOW 0
#define BLOCK 1
#define LOGGING 2
#define NUM_THREADS 4

static volatile bool running = true;

static void sig_handler(int sig) {
    running = false;
}

typedef enum {
    RUNTIME_UNKNOWN,
    RUNTIME_DOCKER,
    RUNTIME_CONTAINERD,
    RUNTIME_CRIO
} ContainerRuntime;

ContainerRuntime get_runtime_from_user() {
    char input[20];
    struct sigaction sa_int{};
    sa_int.sa_handler = sig_handler;
    sa_int.sa_flags = 0;
    sigemptyset(&sa_int.sa_mask);
    sigaction(SIGINT, &sa_int, NULL);
    
    printf("Enter container runtime (docker/containerd/crio): ");
    if (fgets(input, sizeof(input), stdin) == NULL || !running) {
        printf("\nExiting...\n");
        exit(0);
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
            return get_docker_pid(container_name);
        case RUNTIME_CONTAINERD:
            return get_containerd_pid(container_name);
        case RUNTIME_CRIO:
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

    __u32 ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1) {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 1;
    }

    printf("PID namespace ID for PID %d: %u\n", container_pid, ns_id);

    close(fd);
    return ns_id;
}

void get_user_input(struct tracepoint_bpf *skel, __u32 ns_id) {
    __u32 action = LOGGING;
    int err;
    
    long syscalls[] = {
        __NR_socket, __NR_socketpair, __NR_setsockopt, __NR_getsockopt,
        __NR_getsockname, __NR_getpeername, __NR_bind, __NR_listen,
        __NR_accept, __NR_accept4, __NR_connect, __NR_shutdown,
        __NR_recvfrom, __NR_recvmsg, __NR_recvmmsg, __NR_sendto,
        __NR_sendmsg, __NR_sendmmsg, __NR_sethostname, __NR_setdomainname, 
        __NR_ioctl, __NR_poll, __NR_ppoll, __NR_epoll_create, 
        __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait, 
        __NR_epoll_pwait2
    };

    for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
        struct event_key key{};
        key.ns_id = ns_id;
        key.event_id = syscalls[i];
        
        err = bpf_map__update_elem(skel->maps.event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update map for enter event: %d\n", err);
            continue;
        }
        
        printf("Updated map for syscall %ld\n", syscalls[i]);
    }
}

static time_t get_boot_time() {
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        fprintf(stderr, "Error getting system info\n");
        return -1;
    }
    time_t current_time = time(NULL);

    return current_time - si.uptime;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tracepoint_bpf *skel;
    struct ring_buffer *rb;
    ContainerRuntime runtime;
    char container_str[256];
    __u32 ns_id, pid;
    int err;

    time_t boot_time = get_boot_time();
    if (boot_time == -1) {
        fprintf(stderr, "Failed to get boot time\n");
        goto cleanup;
    }

    init_event_handlers();
    skel = tracepoint_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        goto cleanup;
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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");

    runtime = get_runtime_from_user();

    printf("Enter container name to restrict (or 'quit' to exit): ");
    if (fgets(container_str, sizeof(container_str), stdin) == NULL || !running) {
        printf("\nExiting...\n");
        goto cleanup;
    }
    container_str[strcspn(container_str, "\n")] = 0;
    if (strcmp(container_str, "quit") == 0) {
        printf("Exiting...\n");
        goto cleanup;
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
            goto cleanup;
    }
    ns_id = get_namespace_id(pid);
    get_user_input(skel, ns_id);

    printf("\nMonitoring started. Press Ctrl+C to exit...\n\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            printf("\nExiting...\n");
            break;
        } else if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    running = false;
    tracepoint_bpf__destroy(skel);
    return err != 0;
}