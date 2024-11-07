// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
 
#include "enforcement.skel.h"

#include "container_info.h"
#include "policy_map_structs.h"
#include "parser.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define MAP_PIN_PATH "/sys/fs/bpf/policy_map"
#define POLICY_FILE_PATH "/policy/policy.yaml"
#define POLICY_UPDATE_INTERVAL 60

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

static volatile bool exiting = false;

void clear_bpf_map(int map_fd);

bool file_exists(const char *path) {
    struct stat buffer;
    return stat(path, &buffer) == 0;
}

static int print_event(void *ctx, void *data, size_t data_sz) {
    event *e = (event *)data;
    char timestamp[32];
    time_t event_time = e->ts / 1000000000;  // Convert nanoseconds to seconds
    struct tm *tm_info = localtime(&event_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("--------- Event ---------\n"
           "Timestamp: %s.%09llu\n"
           "Container ID: pid_ns=%u, mnt_ns=%u\n"
           "Process: host_ppid=%u, host_pid=%u, ppid=%u, pid=%u, uid=%u\n"
           "Cgroup ID: %llu\n"
           "Event ID: %d\n"
           "Return Value: %lld\n"
           "Command: %s\n"
           "Data:\n"
           "  Path: %s\n"
           "  Source: %s\n"
           "--------------------------\n\n",
           timestamp, e->ts % 1000000000, e->pid_id, e->mnt_id, e->host_ppid, e->host_pid, e->ppid, e->pid, e->uid,
           e->cgroup_id, e->event_id, e->retval, e->comm, e->data.path, e->data.source);

    return 0;
}

void handle_signal(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int get_docker_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "docker inspect -f '{{.State.Pid}}' %s", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run docker command");
        return 0;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return 0;
    }
    pclose(fp);

    return atoi(output);
}

unsigned long get_pid_ns_id(pid_t container_pid) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", container_pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open namespace file");
        return 0;
    }

    char link_target[MAX_PATH_LENGTH];
    ssize_t len = readlink(path, link_target, sizeof(link_target)-1);
    if (len < 0) {
        perror("Failed to read link");
        close(fd);
        return 0;
    }
    link_target[len] = '\0';

    unsigned int ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1) {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 0;
    }

    close(fd);
    return ns_id;
}

unsigned long get_mnt_ns_id(pid_t container_pid) {
    char path[MAX_PATH_LENGTH];
    char buf[MAX_PATH_LENGTH];
    ssize_t len;
    int fd;
    unsigned long mnt_ns_id = 0;

    // Create mnt ns path
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", container_pid);

    // Open namespace File
    fd = open(path, O_RDONLY);
    if (fd == 0) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 0;
    }

    // Read symling
    len = readlink(path, buf, sizeof(buf) - 1);
    if (len == -1) {
        fprintf(stderr, "Failed to read link %s: %s\n", path, strerror(errno));
        close(fd);
        return 0;
    }
    buf[len] = '\0';

    // get namespace id
    if (sscanf(buf, "mnt:[%lu]", &mnt_ns_id) != 1) {
        fprintf(stderr, "Failed to parse mount namespace ID from: %s\n", buf);
        close(fd);
        return 0;
    }

    close(fd);
    return mnt_ns_id;
}

struct policy_key make_policy_key(pid_t pid){
    struct policy_key key;
    key.pid_ns_id = get_pid_ns_id(pid);
    key.mnt_ns_id = get_mnt_ns_id(pid);
    return key;
}

void print_policies(int map_fd) {
    struct policy_key key = {0}, next_key;
    struct policy_value value;

    // Iterate over all keys in the map
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        // Lookup value for the next_key
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            // Print key (Container ID)
            printf("Container ID: pid_ns=%u, mnt_ns=%u\n", next_key.pid_ns_id, next_key.mnt_ns_id);
            printf("Source: %s\n", value.source);

            // Print file policies
            printf("File Policies:\n");
            for (__u32 i = 0; i < value.num_file_policies; i++) {
                printf("  Path: %s\n", value.file_policies[i].path);
                printf("  Flags: ");
                for (const auto &flag: flags_to_string(value.file_policies[i].flags)) cout << flag << " ";
                printf("\n");
            }

            // Print network policies
            printf("Network Policies:\n");
            for (__u32 i = 0; i < value.num_network_policies; i++) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(value.network_policies[i].ip), ip_str, INET_ADDRSTRLEN);
                int prefix_len = 32;
                uint32_t mask = value.network_policies[i].subnet_mask;
                if (!mask) {
                    prefix_len = 0;
                }
                else {
                    while ((mask & 1) == 0) {
                        prefix_len--;
                        mask >>= 1;
                    }
                }

                printf("  IP: %s/%d, Port: %u, Protocol: %u\n", ip_str, prefix_len, ntohs(value.network_policies[i].port), value.network_policies[i].protocol);
                printf("  Flags: ");
                for (const auto &flag: flags_to_string(value.network_policies[i].flags)) cout << flag << " ";
                printf("\n");
            }

            // Print process policies
            printf("Process Policies:\n");
            for (__u32 i = 0; i < value.num_process_policies; i++) {
                printf("  Command: %s\n", value.process_policies[i].comm);
                printf("  Flags: ");
                for (const auto &flag: flags_to_string(value.process_policies[i].flags)) cout << flag << " ";
                printf("\n");
            }

            // Print a separator for each container entry
            printf("\n");
        }

        // Move to the next key
        key = next_key;
    }
}

void flush_input_buffer() {
    int ch;
    // Loop until the newline character or EOF is found
    while ((ch = getchar()) != '\n' && ch != EOF);
}

int get_yes_no_input(const char* prompt) {
    char input[10];
    printf("%s [y/N]: ", prompt);
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return -1;
    }
    input[strcspn(input, "\n")] = 0;  // Remove newline if present
    return (tolower(input[0]) == 'y');
}

int add_policy(int map_fd) {
    struct policy_key key;
    struct policy_value value;

    // Get container ID
    printf("Enter container ID (container_name): ");
    char container_name[256];
    if (!fgets(container_name, sizeof(container_name), stdin)) {
        return -1;
    }
    container_name[strcspn(container_name, "\n")] = '\0';

    int container_pid = get_docker_pid(container_name);

    // Get container pid namespace && mnt namespace by container name
    key = make_policy_key(container_pid);

    printf("pid ns: %u mnt ns: %u\n", key.pid_ns_id, key.mnt_ns_id);
    
    // Check if the key can be reused in the bpf map
    if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
        memset(&value, 0, sizeof(struct policy_value));
    }

    // Get policy type
    int policy_type;
    printf("Enter policy type (0: File, 1: Network, 2: Process): ");
    if (scanf("%d", &policy_type) != 1) {
        fprintf(stderr, "Invalid input for policy type\n");
        return -1;
    }
    getchar(); // Consume newline

    switch (policy_type) {
        case POLICY_FILE: {
            struct file_policy *fp = &value.file_policies[value.num_file_policies];
            printf("Enter file path: ");
            if (fgets(fp->path, sizeof(fp->path), stdin) == NULL) {
                fprintf(stderr, "Failed to read file path\n");
                return -1;
            }
            fp->path[strcspn(fp->path, "\n")] = 0;

            if (get_yes_no_input("Block Read")) fp->flags |= POLICY_FILE_READ;
            if (get_yes_no_input("Block Write")) fp->flags |= POLICY_FILE_WRITE;
            if (get_yes_no_input("Block Execute")) fp->flags |= POLICY_FILE_EXEC;
            if (get_yes_no_input("Block Append")) fp->flags |= POLICY_FILE_APPEND;
            if (get_yes_no_input("Block Rename")) fp->flags |= POLICY_FILE_RENAME;
            if (get_yes_no_input("Block Delete")) fp->flags |= POLICY_FILE_DELETE;
            if (get_yes_no_input("Leave a log")) fp->flags |= POLICY_AUDIT;
            if (get_yes_no_input("Explicit Deny")) fp->flags |= POLICY_DENY;
            else fp->flags |= POLICY_ALLOW;
            if (get_yes_no_input("Owner Policy")) fp->flags |= POLICY_OWNER;
            if (get_yes_no_input("Recursive Policy in Dir")) fp->flags |= POLICY_RECURSIVE;
            
            value.num_file_policies++;
            break;
        }
        case POLICY_NETWORK: {
            struct network_policy *np = &value.network_policies[value.num_network_policies];
            char ip_str[INET_ADDRSTRLEN];
            printf("Enter IP address: ");
            if (scanf("%s", ip_str) != 1) {
                fprintf(stderr, "Invalid input for IP address\n");
                return -1;
            }
            if (inet_pton(AF_INET, ip_str, &np->ip) != 1) {
                fprintf(stderr, "Invalid IP address\n");
                return -1;
            }
            printf("Enter port(For ALL, enter 0): ");
            unsigned short port;
            if (scanf("%hu", &port) != 1) {
                fprintf(stderr, "Invalid input for port\n");
                return -1;
            }
            np->port = htons(port);
            printf("Enter protocol (ICMP=1, TCP=6, UDP=17, IGMP=2, IPv4=4, IPv6=6, ALL=0): ");
            if (scanf("%hhu", &np->protocol) != 1) {
                fprintf(stderr, "Invalid input for protocol\n");
                return -1;
            }

            flush_input_buffer();
            printf("Enter network policy\n");
            if (get_yes_no_input("Block Network connect")) np->flags |= POLICY_NET_CONNECT;
            if (get_yes_no_input("Block Inbound traffic")) np->flags |= POLICY_NET_SRC;
            if (get_yes_no_input("Block Outbound traffic")) np->flags |= POLICY_NET_DST;

            if (get_yes_no_input("Leave a log")) np->flags |= POLICY_AUDIT;
            if (get_yes_no_input("Explicit Deny")) np->flags |= POLICY_DENY;
            else np->flags |= POLICY_ALLOW;
            if (get_yes_no_input("Owner Policy")) np->flags |= POLICY_OWNER;

            value.num_network_policies++;
            break;
        }
        case POLICY_PROCESS: {
            struct process_policy *pp = &value.process_policies[value.num_process_policies];
            printf("Enter process command: ");
            fflush(stdin);
            if (fgets(pp->comm, sizeof(pp->comm), stdin) == NULL) {
                fprintf(stderr, "Failed to read process command\n");
                return -1;
            }
            pp->comm[strcspn(pp->comm, "\n")] = 0;

            if (get_yes_no_input("Block Fork")) pp->flags |= POLICY_PROC_FORK;
            if (get_yes_no_input("Block Executing a program in a process")) pp->flags |= POLICY_PROC_EXEC;
            if (get_yes_no_input("Block Kill")) pp->flags |= POLICY_PROC_KILL;

            if (get_yes_no_input("Leave a log")) pp->flags |= POLICY_AUDIT;
            if (get_yes_no_input("Explicit Deny")) pp->flags |= POLICY_DENY;
            else pp->flags |= POLICY_ALLOW;
            if (get_yes_no_input("Owner Policy")) pp->flags |= POLICY_OWNER;

            value.num_process_policies++;
            break;
        }
        default:
            fprintf(stderr, "Invalid policy type\n");
            return -1;
    }

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
        fprintf(stderr, "Failed to Add policy: mnt ns: %u, pid ns: %u\n", key.mnt_ns_id, key.pid_ns_id);
    }

    return 0;
}

int update_policy_with_file(int map_fd, char* abs_file_name) {
    const rfl::Result<YamlPolicy> result = rfl::yaml::load<YamlPolicy>(abs_file_name);
    YamlPolicy policy = result.value();

    if (policy.containers.empty()) {
        fprintf(stderr, "No policy found in the file\n");
        return -1;
    }

    clear_bpf_map(map_fd);

    for (const YamlContainerPolicy& container : policy.containers) {
        struct policy_key key;
        struct policy_value value;

        int container_pid = get_docker_pid(container.container_name.c_str());
        if (!container_pid) {
            fprintf(stderr, "Failed to get container pid: %s\n", container.container_name.c_str());
            continue;
        }

        key = make_policy_key(container_pid);
        if (!key.pid_ns_id || !key.mnt_ns_id) {
            fprintf(stderr, "Failed to get namespace ID\n");
            continue;
        }
        printf("Container %s(%u %u)-%d\n", container.container_name.c_str(), key.pid_ns_id, key.mnt_ns_id, container_pid);
        
        //file policies
        if (!(container.lsm_policies.file.empty())) {
            value.num_file_policies = 0;
            for (const auto& file : container.lsm_policies.file) {
                strcpy(value.file_policies[value.num_file_policies].path, file.path.c_str());
                value.file_policies[value.num_file_policies].flags = string_to_flags(file.flags);
                
                for (std::vector<int>::size_type i = 0; i < file.uid.size(); i++) {
                    value.file_policies[value.num_file_policies].uid[i] = file.uid[i];
                }
                value.num_file_policies++;
            }
        }
        
        // network policies
        if (!(container.lsm_policies.network.empty())) {
            value.num_network_policies = 0;
            for (const auto& network : container.lsm_policies.network) {
                char ip_str[INET_ADDRSTRLEN];
                IpAddress ip = parse_ip(network.ip);
                uint32_t ip_network_order = htonl(ip.ip);
                inet_ntop(AF_INET, &ip_network_order, ip_str, INET_ADDRSTRLEN);
                inet_pton(AF_INET, ip_str, &value.network_policies[value.num_network_policies].ip);
                value.network_policies[value.num_network_policies].subnet_mask = ip.subnet_mask;
                value.network_policies[value.num_network_policies].port = network.port;
                value.network_policies[value.num_network_policies].protocol = network.protocol;
                value.network_policies[value.num_network_policies].flags = string_to_flags(network.flags);
                
                for (std::vector<int>::size_type i = 0; i < network.uid.size(); i++) {
                    value.file_policies[value.num_network_policies].uid[i] = network.uid[i];
                }
                value.num_network_policies++;
            }
        }
        
        // process policies
        if (!(container.lsm_policies.process.empty())) {
            value.num_process_policies = 0;
            for (const auto& process : container.lsm_policies.process) {
                strcpy(value.process_policies[value.num_process_policies].comm, process.comm.c_str());
                value.process_policies[value.num_process_policies].flags = string_to_flags(process.flags);
                
                for (std::vector<int>::size_type i = 0; i < process.uid.size(); i++) {
                    value.process_policies[value.num_process_policies].uid[i] = process.uid[i];
                }
                value.num_process_policies++;
            }
        }

        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
            fprintf(stderr, "Failed to Add policy: mnt ns: %u, pid ns: %u\n", key.mnt_ns_id, key.pid_ns_id);
        }
    }
    return 0;
}

void update_policy_periodically(int map_fd) {
    while (true) {
        // Call the update function
        if (update_policy_with_file(map_fd, POLICY_FILE_PATH) == 0) {
            std::cout << "update_policy_with_file called successfully.\n" << std::endl;
        } else {
            std::cerr << "Failed to call update_policy_with_file." << std::endl;
        }
        
        // Sleep for 60 seconds
        std::this_thread::sleep_for(std::chrono::seconds(POLICY_UPDATE_INTERVAL));
    }
}

enum view_mode {
    ADD_POLICY,
    UPDATE_POLICY_FILE,
    DELETE_POLICY,
    SHOW_POLICY,
    SHOW_LOG,
    EXIT
};

void print_menu() {
    char *menu[] = {
        "Add Policy",
        "Update policy with file",
        "Delete Policy",
        "Show Policy",
        "Show Log",
        "Exit"
    };
    
    printf("input number to select menu\n");


    __u64 i=0;
    for (i = 0; i < sizeof(menu) / sizeof(menu[0]); i++) {
        printf("  %lld. %s\n", i, menu[i]);
    }
}

int get_menu(char *input) {
    if (strcmp(input, "1") == 0) {
        return ADD_POLICY;
    } else if (strcmp(input, "2") == 0) {
        return UPDATE_POLICY_FILE;
    }  else if (strcmp(input, "3") == 0) {
        return DELETE_POLICY;
    } else if (strcmp(input, "4") == 0) {
        return SHOW_POLICY;
    } else if (strcmp(input, "5") == 0) {
        return SHOW_LOG;
    } else if (strcmp(input, "6") == 0) {
        return EXIT;
    } else {
        return -1;
    }
}

void clear_bpf_map(int map_fd) {
    struct policy_key key, next_key;
    
    // Start by fetching the first key
    if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        // While there are still elements in the map
        do {
            key = next_key;
            // Try to delete the current key
            if (bpf_map_delete_elem(map_fd, &key) != 0) {
                perror("Failed to delete map element");
                break;  // Stop on delete failure
            }
            // Fetch the next key
        } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0);
    }
}


int main(int argc, char **argv) {
    struct enforcement_bpf *skel;
    struct ring_buffer *rb = NULL;
    int map_fd = -1;
    int status = 0;

    /* Set up libbpf errors and debug info callback */
    // libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = enforcement_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    int err = enforcement_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = enforcement_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.policy_map);
    // check if the map already exists
    if (map_fd < 0) {
        fprintf(stderr, "No existing map found, creating a new one.\n");

        err = bpf_object__pin_maps(skel->obj, BPF_FS_PATH);
        if (err) {
            fprintf(stderr, "Failed to pin maps: %d\n", err);
            goto cleanup;
        }

        map_fd = bpf_obj_get(MAP_PIN_PATH);
        if (map_fd < 0) {
            fprintf(stderr, "Failed to open pinned map: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    else {
        fprintf(stdout, "Found existing map, reusing it.\n");

        bpf_map__set_pin_path(skel->maps.policy_map, MAP_PIN_PATH);
        err = bpf_map__reuse_fd(skel->maps.policy_map, map_fd);
        if (err) {
            fprintf(stderr, "Failed to reuse existing map: %d\n", err);
            goto cleanup;
        }
    }

    {
        std::cout << "컨테이너 PID 자동 감지 중...\n";
        int detected_containers = ContainerManager::getContainerPIDs();
        if (detected_containers <= 0) {
            std::cerr << "실행 중인 컨테이너를 찾을 수 없습니다.\n";
            goto cleanup;
        }
        std::cout << detected_containers << "개의 컨테이너를 감지했습니다.\n";

        for (const auto &container : ContainerManager::containers) {
            __u32 key_pid = static_cast<__u32>(container.pid);
            __u32 value_pid = 1;
            __u64 key_inode = static_cast<__u64>(ContainerManager::getContainerInode(container.id));
            __u64 value_inode = 1;

            err = bpf_map__update_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), &value_pid, sizeof(value_pid), BPF_ANY);
            if (err) {
                std::cerr << "컨테이너 PID " << container.pid << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                continue;
            }

            err = bpf_map__update_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), &value_inode, sizeof(value_inode), BPF_ANY);
            if (err) {
                std::cerr << "컨테이너 inode " << key_inode << "를 맵에 추가하는데 실패했습니다: " << strerror(errno) << "\n";
                // PID 맵에서 제거
                bpf_map__delete_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), BPF_ANY);
                continue;
            }

            std::cout << "컨테이너 ID: " << container.id << ", PID: " << container.pid << ", inode: " << key_inode << "를 모니터링 중\n";
        }
    }

    // 링 버퍼 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), print_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed Create Ring Buffer\n");
        goto cleanup;
    }

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    status = UPDATE_POLICY_FILE;

    while (!exiting) {
        // char cmd[256];
        // print_menu();
        // printf("> ");
        // if (!fgets(cmd, sizeof(cmd), stdin)) {
        //     break;
        // }

        // cmd[strcspn(cmd, "\n")] = 0;
        // int mode = get_menu(cmd);  

        switch (status) {
        case ADD_POLICY:
            printf("Add Policy\n");
            printf("Adding a new policy\n");
            if (add_policy(map_fd) == 0) {
                printf("Policy added successfully\n");
            } else {
                printf("Failed to add policy\n");
            }
            break;
        case UPDATE_POLICY_FILE:
            printf("Tryin to update policy with file...\n");

            if (file_exists(POLICY_FILE_PATH)) {
                // Create a new thread to periodically update the policy
                std::thread policy_update_thread(update_policy_periodically, map_fd);
                
                // Detach the thread so it runs independently
                policy_update_thread.detach();
                
                std::cout << "Policy update thread started, updating every minute.\n" << std::endl;
                status = SHOW_LOG;
            } else {
                std::cout << "Policy file not found\n";
            }
            break;
        case DELETE_POLICY:
            printf("Delete Policy\n");
            clear_bpf_map(map_fd);
            printf("Policy map cleared.\n");
            break;
        case SHOW_POLICY:
            printf("Show Policy\n");
            print_policies(map_fd);
            break;
        case SHOW_LOG:
            err = ring_buffer__poll(rb, 1 /* timeout, ms */);
            if (err < 0) {
                printf("Error polling ring buffer: %d\n", err);
                goto cleanup;
            } else if (err > 0) {
                printf("Processed %d events\n", err);
            }
            break;
        case EXIT:
            goto cleanup;
            break;
        default:
            printf("Invalid Input\n");
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    enforcement_bpf__destroy(skel);
    return -err;
}