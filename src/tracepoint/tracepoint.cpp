#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <asm/unistd_64.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <thread>
#include <chrono>
#include "tracepoint.skel.h"
#include "struct.h"
#include "handler.h"
#include "parser.h"
#include "db.h"

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256
#define MAX_PATH 256
#define ALLOW 0
#define BLOCK 1
#define LOGGING 2
#define POLICY_UPDATE_INTERVAL 60
#define POLICY_FILE_PATH const_cast<char*>("/policy/policy.yaml")

static volatile bool running = true;
std::unique_ptr<DBConnection> g_db_connection;

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

__u32 get_namespace_id(int container_pid) {
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

static time_t get_boot_time() {
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        fprintf(stderr, "Error getting system info\n");
        return -1;
    }
    time_t current_time = time(NULL);
    return current_time - si.uptime;
}

int update_policy_with_file(struct bpf_map *event_policy_map, char* abs_file_name) {
    __u32 action = LOGGING;
    int err;
    const rfl::Result<YamlPolicy> result = rfl::yaml::load<YamlPolicy>(abs_file_name);
    YamlPolicy policy = result.value();

    if (policy.containers.empty()) {
        fprintf(stderr, "No policy found in the file\n");
        return -1;
    }

    for (const YamlContainerPolicy& container: policy.containers) {
        struct event_key key{};
        vector<int> syscall_list = string_to_syscalls(container.tracepoint_policy.syscalls);

        __u32 container_pid = get_docker_pid(container.container_name.c_str());
        if (!container_pid) {
            fprintf(stderr, "Failed to get container pid: %s\n", container.container_name.c_str());
            continue;
        }
        __u32 ns_id = get_namespace_id(container_pid);

        for (size_t i = 0; i < syscall_list.size(); i++) {
            key.ns_id = ns_id;
            key.event_id = syscall_list[i];
            
            err = bpf_map__update_elem(event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update map for enter event: %d\n", err);
                continue;
            }
            
            printf("Updated map for syscall %d\n", syscall_list[i]);
        }
    }

    return 0;
}

bool file_exists(const char *file_path) {
    struct stat buffer;
    return stat(file_path, &buffer) == 0;
}

void update_policy_periodically(struct bpf_map *event_policy_map) {
    while (true) {
        // Call the update function
        if (update_policy_with_file(event_policy_map, POLICY_FILE_PATH) == 0) {
            std::cout << "update_policy_with_file called successfully.\n" << std::endl;
        } else {
            std::cerr << "Failed to call update_policy_with_file." << std::endl;
        }
        
        // Sleep for 60 seconds
        std::this_thread::sleep_for(std::chrono::seconds(POLICY_UPDATE_INTERVAL));
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tracepoint_bpf *skel;
    struct ring_buffer *rb;
    int err;

    boot_time = get_boot_time();
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

    while (running) {
        if (file_exists(POLICY_FILE_PATH)) {
            // Create a new thread to periodically update the policy
            std::thread policy_update_thread(update_policy_periodically, skel->maps.event_policy_map);
            
            // Detach the thread so it runs independently
            policy_update_thread.detach();
            
            std::cout << "Policy update thread started, updating every minute.\n" << std::endl;
            break;
        } else {
            std::cout << "Policy file not found\n";
            sleep(10);
        }
    }

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
    g_db_connection.reset();
    if (rb)
        ring_buffer__free(rb);
    tracepoint_bpf__destroy(skel);
    return err != 0;
}