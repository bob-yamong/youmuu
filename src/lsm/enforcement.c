#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "enforcement.skel.h"

#include "policy_map_structs.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define MAP_PIN_PATH "/sys/fs/bpf/policy_map"

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

static volatile bool exiting = false;

static int print_event(void *ctx, void *data, size_t data_sz) {
    event *e = (event *)data;
    char timestamp[32];
    time_t event_time = e->ts / 1000000000;  // Convert nanoseconds to seconds
    struct tm *tm_info = localtime(&event_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("--------- Event ---------\n");
    printf("Timestamp: %s.%09llu\n", timestamp, e->ts % 1000000000);
    printf("Container ID: pid_ns=%u, mnt_ns=%u\n", e->pid_id, e->mnt_id);
    printf("Process: host_ppid=%u, host_pid=%u, ppid=%u, pid=%u, uid=%u\n", 
           e->host_ppid, e->host_pid, e->ppid, e->pid, e->uid);
    printf("Cgroup ID: %llu\n", e->cgroup_id);
    printf("Event ID: %d\n", e->event_id);
    printf("Return Value: %lld\n", e->retval);
    printf("Command: %s\n", e->comm);
    printf("Data:\n");
    printf("  Path: %s\n", e->data.path);
    printf("  Source: %s\n", e->data.source);
    printf("--------------------------\n\n");

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
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
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
        return 1;
    }

    char link_target[MAX_PATH_LENGTH];
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
    if (fd == -1) {
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
            for (int i = 0; i < value.num_file_policies; i++) {
                printf("  Path: %s\n", value.file_policies[i].path);
                printf("  Flags: ");
                if (value.file_policies[i].flags & POLICY_FILE_READ) printf("READ ");
                if (value.file_policies[i].flags & POLICY_FILE_WRITE) printf("WRITE ");
                if (value.file_policies[i].flags & POLICY_FILE_EXEC) printf("EXEC ");
                if (value.file_policies[i].flags & POLICY_FILE_APPEND) printf("APPEND ");
                if (value.file_policies[i].flags & POLICY_FILE_RENAME) printf("RENAME ");
                if (value.file_policies[i].flags & POLICY_FILE_DELETE) printf("DELETE ");
                printf("\n");
            }

            // Print network policies
            printf("Network Policies:\n");
            for (int i = 0; i < value.num_network_policies; i++) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(value.network_policies[i].ip), ip_str, INET_ADDRSTRLEN);
                printf("  IP: %s, Port: %u, Protocol: %u\n", ip_str, ntohs(value.network_policies[i].port), value.network_policies[i].protocol);
                printf("  Flags: ");
                if (value.network_policies[i].flags & POLICY_NET_CONNECT) printf("CONNECT ");
                if (value.network_policies[i].flags & POLICY_NET_BIND) printf("BIND ");
                if (value.network_policies[i].flags & POLICY_NET_ACCEPT) printf("ACCEPT ");
                if (value.network_policies[i].flags & POLICY_NET_SEND) printf("SEND ");
                if (value.network_policies[i].flags & POLICY_NET_RECV) printf("RECV ");
                printf("\n");
            }

            // Print process policies
            printf("Process Policies:\n");
            for (int i = 0; i < value.num_process_policies; i++) {
                printf("  Command: %s\n", value.process_policies[i].comm);
                printf("  Flags: ");
                if (value.process_policies[i].flags & POLICY_PROC_FORK) printf("FORK ");
                if (value.process_policies[i].flags & POLICY_PROC_EXEC) printf("EXEC ");
                if (value.process_policies[i].flags & POLICY_PROC_KILL) printf("KILL ");
                if (value.process_policies[i].flags & POLICY_PROC_PTRACE) printf("PTRACE ");
                printf("\n");
            }

            // Print a separator for each container entry
            printf("\n");
        }

        // Move to the next key
        key = next_key;
    }
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
        char input;
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
            printf("Enter port: ");
            unsigned short port;
            if (scanf("%hu", &port) != 1) {
                fprintf(stderr, "Invalid input for port\n");
                return -1;
            }
            np->port = htons(port);
            printf("Enter protocol: ");
            if (scanf("%hhu", &np->protocol) != 1) {
                fprintf(stderr, "Invalid input for protocol\n");
                return -1;
            }

            if (get_yes_no_input("Block Network connect")) np->flags |= POLICY_NET_CONNECT;
            if (get_yes_no_input("Block Network bind")) np->flags |= POLICY_NET_BIND;
            if (get_yes_no_input("Block Nework Accept")) np->flags |= POLICY_NET_ACCEPT;
            if (get_yes_no_input("Block Net Send")) np->flags |= POLICY_NET_SEND;
            if (get_yes_no_input("Block Net Recv")) np->flags |= POLICY_NET_RECV;

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
            getchar(); // Consume newline
            if (fgets(pp->comm, sizeof(pp->comm), stdin) == NULL) {
                fprintf(stderr, "Failed to read process command\n");
                return -1;
            }
            pp->comm[strcspn(pp->comm, "\n")] = 0;

            if (get_yes_no_input("Block Fork")) pp->flags |= POLICY_PROC_FORK;
            if (get_yes_no_input("Block Executing a program in a process")) pp->flags |= POLICY_PROC_EXEC;
            if (get_yes_no_input("Leave a log")) pp->flags |= POLICY_PROC_KILL;
            if (get_yes_no_input("Leave a log")) pp->flags |= POLICY_PROC_PTRACE;

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
        fprintf(stderr, "Failed to Add policy: mnt ns: %u, pid ns: %u\n", key.mnt_ns_id, key.pid_ns_id, strerror(errno));
    } 

    return 0;
}

enum view_mode {
    ADD_POLICY,
    DELETE_POLICY,
    SHOW_POLICY,
    SHOW_LOG,
    EXIT
};

void print_menu() {
    char *menu[] = {
        "Add Policy",
        "Delete Policy",
        "Show Policy",
        "Show Log",
        "Exit"
    };
    
    printf("input number to select menu\n");

    for (int i = 0; i < sizeof(menu) / sizeof(menu[0]); printf("  %d. %s\n", i, menu[i++]));
}

enum view_mode get_menu(char *input) {
    if (strcmp(input, "1") == 0) {
        return ADD_POLICY;
    } else if (strcmp(input, "2") == 0) {
        return DELETE_POLICY;
    } else if (strcmp(input, "3") == 0) {
        return SHOW_POLICY;
    } else if (strcmp(input, "4") == 0) {
        return SHOW_LOG;
    } else if (strcmp(input, "5") == 0) {
        return EXIT;
    } else {
        return -1;
        
    }
}

int main(int argc, char **argv)
{
    struct enforcement_bpf *skel;
    struct ring_buffer *rb = NULL;

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = enforcement_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    int err, map_fd = bpf_obj_get(MAP_PIN_PATH);

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
    } else {
        fprintf(stdout, "Found existing map, reusing it.\n");

        bpf_map__set_pin_path(skel->maps.policy_map, MAP_PIN_PATH);
        err = bpf_map__reuse_fd(skel->maps.policy_map, map_fd);
        if (err) {
            fprintf(stderr, "Failed to reuse existing map: %d\n", err);
            goto cleanup;
        }
    }

    err = enforcement_bpf__load(skel);
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

    // 링 버퍼 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), print_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed Create Ring Buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");


    enum view_mode mode;
    while (!exiting) {
        char cmd[256];
        print_menu();
        printf("> ");
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }

        cmd[strcspn(cmd, "\n")] = 0;
        mode = get_menu(cmd);

        switch (mode)
        {
        case ADD_POLICY:
            printf("Add Policy\n");
            printf("Adding a new policy\n");
            if (add_policy(map_fd) == 0) {
                printf("Policy added successfully\n");
            } else {
                printf("Failed to add policy\n");
            }
            break;
        case DELETE_POLICY:
            printf("Delete Policy\n");
            break;
        case SHOW_POLICY:
            printf("Show Policy\n");
            print_policies(map_fd);
            break;
        case SHOW_LOG:
            err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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