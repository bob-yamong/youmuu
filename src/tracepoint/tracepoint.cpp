#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <chrono>
#include <asm/unistd_64.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <syslog.h>
#include <utility>
#include "getEnv.h"
#include "tracepoint.skel.h"
#include "struct.h"
#include "handler.h"
#include "parser.h"
#include "db.h"
#include "container_pid_id.h"

#define MAX_PATH 256
#define ALLOW 0
#define BLOCK 1
#define LOGGING 2
#define POLICY_FILE_PATH const_cast<char*>("/policy/policy.yaml")

static volatile bool running = true;
std::unique_ptr<DBConnection> g_db_connection;
using json = nlohmann::json;

static void sig_handler(int sig) {
    running = false;
}

std::string remove_chunked_encoding(const std::string& response) {
    std::string json_body;
    size_t pos = 0;
    
    while (pos < response.size()) {
        // Find the position of the newline after the chunk size
        size_t chunk_size_end = response.find("\r\n", pos);
        if (chunk_size_end == std::string::npos) break;

        // Convert the chunk size from hexadecimal to decimal
        std::string chunk_size_hex = response.substr(pos, chunk_size_end - pos);
        size_t chunk_size = std::stoul(chunk_size_hex, nullptr, 16);
        
        // Move to the start of the actual data
        pos = chunk_size_end + 2;

        // Add the chunk to the JSON body and move to the next chunk
        json_body += response.substr(pos, chunk_size);
        pos += chunk_size + 2;  // Skip over the data and the trailing \r\n
    }

    return json_body;
}

std::pair<int, std::string> get_docker_pid(const char* container_name) {
    const char* socket_path = "/var/run/docker.sock";
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if (sock < 0) {
        perror("Socket creation failed");
        return {0, ""};
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection to Docker socket failed");
        close(sock);
        return {0, ""};
    }

    // Formulate HTTP request to get container info
    std::string request = "GET /containers/" + std::string(container_name) + "/json HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Connection: close\r\n\r\n";
    
    // Send request
    if (send(sock, request.c_str(), request.size(), 0) < 0) {
        perror("Send request failed");
        close(sock);
        return {0, ""};
    }

    // Receive response
    std::string response;
    char buffer[4096];
    int bytes_received;
    while ((bytes_received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, bytes_received);
    }
    close(sock);

    // Find the start of JSON data after HTTP headers
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) {
        std::cerr << "Invalid response format" << std::endl;
        return {0, ""};
    }

    // Extract the JSON body
    std::string json_str = remove_chunked_encoding(response.substr(pos + 4));

    try {
        json container_info = json::parse(json_str);
        int pid = container_info["State"]["Pid"].get<int>();
        std::string id = container_info["Id"].get<std::string>();
        return {pid, id};
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return {0, ""};
    } catch (const json::type_error& e) {
        std::cerr << "JSON type error: " << e.what() << std::endl;
        return {0, ""};
    }
}

__u32 get_namespace_id(int container_pid) {
    char path[MAX_PATH];

    std::string full_path = env::proc_path + "/" + std::to_string(container_pid) + "/ns/pid";
    snprintf(path, sizeof(path), "%s", full_path.c_str());
    
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

    // clearing monitoring data
    pid_namespace_to_container_id.clear();

    for (const YamlContainerPolicy& container: policy.containers) {
    struct event_key key{};
    vector<int> syscall_list = string_to_syscalls(container.tracepoint_policy.syscalls);

    auto [container_pid, container_id] = get_docker_pid(container.container_name.c_str());
    if (!container_pid) {
        fprintf(stderr, "Failed to get container pid: %s\n", container.container_name.c_str());
        continue;
    }
    __u32 pid_namespace = get_namespace_id(container_pid);

    // Store the pid_namespace and container_id in the hash map
    pid_namespace_to_container_id[pid_namespace] = container_id;

    for (size_t i = 0; i < syscall_list.size(); i++) {
        key.pid_namespace = pid_namespace;
        key.event_id = syscall_list[i];
        
        err = bpf_map__update_elem(event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update map for enter event: %d\n", err);
            continue;
        }
        
        printf("Updated map for syscall %d, Container ID: %s\n", syscall_list[i], container_id.c_str());
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
        std::this_thread::sleep_for(std::chrono::seconds(env::update_interval));
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tracepoint_bpf *skel;
    struct ring_buffer *rb;
    int err;
    
    env::getEnv();

    // Syslog 초기화
    openlog("tracepoint", LOG_PID | LOG_CONS, LOG_USER);

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
    closelog();
    running = false;
    g_db_connection.reset();
    if (rb)
        ring_buffer__free(rb);
    tracepoint_bpf__destroy(skel);
    return err != 0;
}
