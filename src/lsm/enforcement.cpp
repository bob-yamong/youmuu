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
#include <sstream>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <syslog.h>
#include <utility>
#include <sys/sysinfo.h>
#include <atomic>
#include <condition_variable>
#include <sys/inotify.h>
#include <poll.h>

#include "enforcement.skel.h"
#include "policy_map_structs.h"
#include "parser.h"
#include "getEnv.h"
#include "kafkaProducer.h"
#include "container_info.h"
#include "yaml_structs.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define POLICY_FILE_PATH "/policy/policy.yaml"

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

std::atomic<bool> exiting(false);
std::atomic<bool> policy_update_running(false);

int map_fd = -1;
int inotify_fd = -1;

using json = nlohmann::json;

// 함수 선언
void clear_bpf_map(int map_fd);
bool file_exists(const char *path); // 반드시 정의를 포함시켜야 함

// Safe print_event 함수 with context
static int print_event(void *ctx, void *data, size_t data_sz) {
    event *e = (event *)data;
    char timestamp[32];
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        fprintf(stderr, "Error getting system info\n");
        return -1;
    }
    time_t current_time = time(NULL);
    time_t boot_time = current_time - si.uptime;

    time_t event_time = (e->ts / 1000000000) + boot_time;
    struct tm *tm_info = localtime(&event_time);
    if (!tm_info) {
        return -1;
    }
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        return -1;
    }

    std::stringstream event_data;
    event_data << "{\"timestamp\":\"" << timestamp << "." << (e->ts % 1000000000) << "\","
               << "\"container_id\":{\"pid_ns\":" << e->pid_id << ",\"mnt_ns\":" << e->mnt_id << "},"
               << "\"process\":{\"host_ppid\":" << e->host_ppid << ",\"host_pid\":" << e->host_pid
               << ",\"ppid\":" << e->ppid << ",\"pid\":" << e->pid << ",\"uid\":" << e->uid << "},"
               << "\"cgroup_id\":" << e->cgroup_id << ","
               << "\"event_id\":" << e->event_id << ","
               << "\"return_value\":" << e->retval << ","
               << "\"command\":\"" << e->comm << "\","
               << "\"data\":{\"path\":\"" << e->data.path << "\",\"source\":\"" << e->data.source << "\"}}";

    // 컨텍스트를 shared_ptr로 캐스팅
    std::shared_ptr<KafkaProducer>* producer_ptr = static_cast<std::shared_ptr<KafkaProducer>*>(ctx);
    if (producer_ptr && *producer_ptr) {
        if ((*producer_ptr)->send(event_data.str())) {
            printf("Success to send event to Kafka\n");
            return 0;
        }
    }

    fprintf(stderr, "Dropping event after failed attempts\n");
    return -1;
}

// 시그널 핸들러
void handle_signal(int signal) {
    if (signal == SIGINT) {
        std::cerr << "\nSIGINT received, exiting...\n";
        exiting.store(true);
        close(inotify_fd);
    }
}

// libbpf 출력 함수
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

// std::string remove_chunked_encoding(const std::string& response) {
//     std::string json_body;
//     size_t pos = 0;
    
//     while (pos < response.size()) {
//         // Find the position of the newline after the chunk size
//         size_t chunk_size_end = response.find("\r\n", pos);
//         if (chunk_size_end == std::string::npos) break;

//         // Convert the chunk size from hexadecimal to decimal
//         std::string chunk_size_hex = response.substr(pos, chunk_size_end - pos);
//         size_t chunk_size = std::stoul(chunk_size_hex, nullptr, 16);
        
//         // Move to the start of the actual data
//         pos = chunk_size_end + 2;

//         // Add the chunk to the JSON body and move to the next chunk
//         json_body += response.substr(pos, chunk_size);
//         pos += chunk_size + 2;  // Skip over the data and the trailing \r\n
//     }

//     return json_body;
// }


// int get_docker_pid(const char* container_name) {
//     const char* socket_path = "/var/run/docker.sock";
//     int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    
//     if (sock < 0) {
//         perror("Socket creation failed");
//         return 0;
//     }

//     struct sockaddr_un addr{};
//     addr.sun_family = AF_UNIX;
//     strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

//     if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//         perror("Connection to Docker socket failed");
//         close(sock);
//         return 0;
//     }

//     // Formulate HTTP request to get container info
//     std::string request = "GET /containers/" + std::string(container_name) + "/json HTTP/1.1\r\n"
//                           "Host: localhost\r\n"
//                           "Connection: close\r\n\r\n";
    
//     // Send request
//     if (send(sock, request.c_str(), request.size(), 0) < 0) {
//         perror("Send request failed");
//         close(sock);
//         return 0;
//     }

//     // Receive response
//     std::string response;
//     char buffer[4096];
//     int bytes_received;
//     while ((bytes_received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
//         response.append(buffer, bytes_received);
//     }
//     close(sock);

//     // Find the start of JSON data after HTTP headers
//     auto pos = response.find("\r\n\r\n");
//     if (pos == std::string::npos) {
//         std::cerr << "Invalid response format" << std::endl;
//         return 0;
//     }

//     // Extract the JSON body
//     std::string json_str = remove_chunked_encoding(response.substr(pos + 4));

//     try {
//         json container_info = json::parse(json_str);
//         return container_info["State"]["Pid"].get<int>();
//     } catch (const json::parse_error& e) {
//         std::cerr << "JSON parse error: " << e.what() << std::endl;
//         return 0;
//     } catch (const json::type_error& e) {
//         std::cerr << "JSON type error: " << e.what() << std::endl;
//         return 0;
//     }
// }


unsigned long get_pid_ns_id(pid_t container_pid) {
    char path[MAX_PATH_LENGTH];

    std::string full_path = env::proc_path + "/" + std::to_string(container_pid) + "/ns/pid";
    snprintf(path, sizeof(path), "%s", full_path.c_str());

    
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
    std::string full_path = env::proc_path + "/" + std::to_string(container_pid) + "/ns/mnt";
    snprintf(path, sizeof(path), "%s", full_path.c_str());

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

// 정책 키 생성 함수
struct policy_key make_policy_key(pid_t pid){
    struct policy_key key;
    key.pid_ns_id = get_pid_ns_id(pid);
    key.mnt_ns_id = get_mnt_ns_id(pid);
    return key;
}

// void print_policies(int map_fd) {
//     struct policy_key key = {0}, next_key;
//     struct policy_value value;

//     // Iterate over all keys in the map
//     while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
//         // Lookup value for the next_key
//         if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
//             // Print key (Container ID)
//             printf("Container ID: pid_ns=%u, mnt_ns=%u\n", next_key.pid_ns_id, next_key.mnt_ns_id);
//             printf("Source: %s\n", value.source);

//             // Print file policies
//             printf("File Policies:\n");
//             for (__u32 i = 0; i < value.num_file_policies; i++) {
//                 printf("  Path: %s\n", value.file_policies[i].path);
//                 printf("  Flags: ");
//                 for (const auto &flag: flags_to_string(value.file_policies[i].flags)) std::cout << flag << " ";
//                 printf("\n");
//             }

//             // Print network policies
//             printf("Network Policies:\n");
//             for (__u32 i = 0; i < value.num_network_policies; i++) {
//                 char ip_str[INET_ADDRSTRLEN];
//                 inet_ntop(AF_INET, &(value.network_policies[i].ip), ip_str, INET_ADDRSTRLEN);
//                 int prefix_len = 32;
//                 uint32_t mask = value.network_policies[i].subnet_mask;
//                 if (!mask) {
//                     prefix_len = 0;
//                 }
//                 else {
//                     while ((mask & 1) == 0) {
//                         prefix_len--;
//                         mask >>= 1;
//                     }
//                 }

//                 printf("  IP: %s/%d, Port: %u, Protocol: %u\n", ip_str, prefix_len, ntohs(value.network_policies[i].port), value.network_policies[i].protocol);
//                 printf("  Flags: ");
//                 for (const auto &flag: flags_to_string(value.network_policies[i].flags)) std::cout << flag << " ";
//                 printf("\n");
//             }

//             // Print process policies
//             printf("Process Policies:\n");
//             for (__u32 i = 0; i < value.num_process_policies; i++) {
//                 printf("  Command: %s\n", value.process_policies[i].comm);
//                 printf("  Flags: ");
//                 for (const auto &flag: flags_to_string(value.process_policies[i].flags)) std::cout << flag << " ";
//                 printf("\n");
//             }

//             // Print a separator for each container entry
//             printf("\n");
//         }

//         // Move to the next key
//         key = next_key;
//     }
// }

// void flush_input_buffer() {
//     int ch;
//     // Loop until the newline character or EOF is found
//     while ((ch = getchar()) != '\n' && ch != EOF);
// }

// int get_yes_no_input(const char* prompt) {
//     char input[10];
//     printf("%s [y/N]: ", prompt);
//     if (fgets(input, sizeof(input), stdin) == NULL) {
//         fprintf(stderr, "Error reading input\n");
//         return -1;
//     }
//     input[strcspn(input, "\n")] = 0;  // Remove newline if present
//     return (tolower(input[0]) == 'y');
// }

// int add_policy(int map_fd) {
//     struct policy_key key;
//     struct policy_value value;

//     // Get container ID
//     printf("Enter container ID (container_name): ");
//     char container_name[256];
//     if (!fgets(container_name, sizeof(container_name), stdin)) {
//         return -1;
//     }
//     container_name[strcspn(container_name, "\n")] = '\0';

//     int container_pid = get_docker_pid(container_name);

//     // Get container pid namespace && mnt namespace by container name
//     key = make_policy_key(container_pid);

//     printf("pid ns: %u mnt ns: %u\n", key.pid_ns_id, key.mnt_ns_id);
    
//     // Check if the key can be reused in the bpf map
//     if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
//         memset(&value, 0, sizeof(struct policy_value));
//     }

//     // Get policy type
//     int policy_type;
//     printf("Enter policy type (0: File, 1: Network, 2: Process): ");
//     if (scanf("%d", &policy_type) != 1) {
//         fprintf(stderr, "Invalid input for policy type\n");
//         return -1;
//     }
//     getchar(); // Consume newline

//     switch (policy_type) {
//         case POLICY_FILE: {
//             struct file_policy *fp = &value.file_policies[value.num_file_policies];
//             printf("Enter file path: ");
//             if (fgets(fp->path, sizeof(fp->path), stdin) == NULL) {
//                 fprintf(stderr, "Failed to read file path\n");
//                 return -1;
//             }
//             fp->path[strcspn(fp->path, "\n")] = 0;

//             if (get_yes_no_input("Block Read")) fp->flags |= POLICY_FILE_READ;
//             if (get_yes_no_input("Block Write")) fp->flags |= POLICY_FILE_WRITE;
//             if (get_yes_no_input("Allow File Create")) fp->flags |= POLICY_FILE_CREATE;
//             if (get_yes_no_input("Block Execute")) fp->flags |= POLICY_FILE_EXEC;
//             if (get_yes_no_input("Block Append")) fp->flags |= POLICY_FILE_APPEND;
//             if (get_yes_no_input("Block Rename")) fp->flags |= POLICY_FILE_RENAME;
//             if (get_yes_no_input("Block Delete")) fp->flags |= POLICY_FILE_DELETE;
//             if (get_yes_no_input("Leave a log")) fp->flags |= POLICY_AUDIT;
//             if (get_yes_no_input("Explicit Deny")) fp->flags |= POLICY_DENY;
//             else fp->flags |= POLICY_ALLOW;
//             if (get_yes_no_input("Owner Policy")) fp->flags |= POLICY_OWNER;
//             if (get_yes_no_input("Recursive Policy in Dir")) fp->flags |= POLICY_RECURSIVE;
            
//             value.num_file_policies++;
//             break;
//         }
//         case POLICY_NETWORK: {
//             struct network_policy *np = &value.network_policies[value.num_network_policies];
//             char ip_str[INET_ADDRSTRLEN];
//             printf("Enter IP address: ");
//             if (scanf("%s", ip_str) != 1) {
//                 fprintf(stderr, "Invalid input for IP address\n");
//                 return -1;
//             }
//             if (inet_pton(AF_INET, ip_str, &np->ip) != 1) {
//                 fprintf(stderr, "Invalid IP address\n");
//                 return -1;
//             }
//             printf("Enter port(For ALL, enter 0): ");
//             unsigned short port;
//             if (scanf("%hu", &port) != 1) {
//                 fprintf(stderr, "Invalid input for port\n");
//                 return -1;
//             }
//             np->port = htons(port);
//             printf("Enter protocol (ICMP=1, TCP=6, UDP=17, IGMP=2, IPv4=4, IPv6=6, ALL=0): ");
//             if (scanf("%hhu", &np->protocol) != 1) {
//                 fprintf(stderr, "Invalid input for protocol\n");
//                 return -1;
//             }

//             flush_input_buffer();
//             printf("Enter network policy\n");
//             if (get_yes_no_input("Block Network connect")) np->flags |= POLICY_NET_CONNECT;
//             if (get_yes_no_input("Block Inbound traffic")) np->flags |= POLICY_NET_SRC;
//             if (get_yes_no_input("Block Outbound traffic")) np->flags |= POLICY_NET_DST;

//             if (get_yes_no_input("Leave a log")) np->flags |= POLICY_AUDIT;
//             if (get_yes_no_input("Explicit Deny")) np->flags |= POLICY_DENY;
//             else np->flags |= POLICY_ALLOW;
//             if (get_yes_no_input("Owner Policy")) np->flags |= POLICY_OWNER;

//             value.num_network_policies++;
//             break;
//         }
//         case POLICY_PROCESS: {
//             struct process_policy *pp = &value.process_policies[value.num_process_policies];
//             printf("Enter process command: ");
//             fflush(stdin);
//             if (fgets(pp->comm, sizeof(pp->comm), stdin) == NULL) {
//                 fprintf(stderr, "Failed to read process command\n");
//                 return -1;
//             }
//             pp->comm[strcspn(pp->comm, "\n")] = 0;

//             if (get_yes_no_input("Block Fork")) pp->flags |= POLICY_PROC_FORK;
//             if (get_yes_no_input("Block Executing a program in a process")) pp->flags |= POLICY_PROC_EXEC;
//             if (get_yes_no_input("Block Kill")) pp->flags |= POLICY_PROC_KILL;

//             if (get_yes_no_input("Leave a log")) pp->flags |= POLICY_AUDIT;
//             if (get_yes_no_input("Explicit Deny")) pp->flags |= POLICY_DENY;
//             else pp->flags |= POLICY_ALLOW;
//             if (get_yes_no_input("Owner Policy")) pp->flags |= POLICY_OWNER;

//             value.num_process_policies++;
//             break;
//         }
//         default:
//             fprintf(stderr, "Invalid policy type\n");
//             return -1;
//     }

//     if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
//         fprintf(stderr, "Failed to Add policy: mnt ns: %u, pid ns: %u\n", key.mnt_ns_id, key.pid_ns_id);
//     }

//     return 0;
// }

int update_policy_with_file(int map_fd, char* abs_file_name) {
    const rfl::Result<YamlPolicy> result = rfl::yaml::load<YamlPolicy>(abs_file_name);
    YamlPolicy policy = result.value();
    
    if (policy.containers.empty()) {
        fprintf(stderr, "No policy found in the file\n");
        return -1;
    }

    ContainerManager::parsed_policy = policy;

    clear_bpf_map(map_fd);

    ContainerManager::monitored_containers.clear(); // 기존 리스트 초기화
    ContainerManager::containers.clear(); // 기존 리스트 초기화
    for (const auto& item : policy.containers) { // YamlPolicy 구조에 따라 수정 필요
        ContainerManager::monitored_containers.push_back(item.container_name);
    }
    // 모니터링할 컨테이너 PID 가져오기
    int detected_containers = ContainerManager::getContainerPIDs();
    if (detected_containers <= 0) {
        std::cerr << "Can not found container for monitoring.\n";
        return -1;
    }


    for (const auto &container : ContainerManager::containers) {
        struct policy_key key;
        struct policy_value value;

        if (container.pid==0) {
            fprintf(stderr, "Failed to get container pid: %s\n", container.name.c_str());
            continue;
        }

        key = make_policy_key(container.pid);
        if (!key.pid_ns_id || !key.mnt_ns_id) {
            fprintf(stderr, "Failed to get namespace ID\n");
            continue;
        }

        printf("Container %s(%u %u)-%d\n", container.name.c_str(), key.pid_ns_id, key.mnt_ns_id, container.pid);
        
        //file policies
        value.num_file_policies = 0;
        if (!(container.lsm_policies.file.empty())) {
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
        value.num_network_policies = 0;
        if (!(container.lsm_policies.network.empty())) {
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
        value.num_process_policies = 0;
        if (!(container.lsm_policies.process.empty())) {
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


// 정책 업데이트 함수
void update_policy_on_event(int map_fd, std::mutex& mtx, std::condition_variable& cv) {
    if (policy_update_running.exchange(true)) {
        std::cerr << "Policy update already in progress, skipping.\n";
        return;
    }

    try {
        std::unique_lock<std::mutex> lock(mtx);

        while (true) {
            if (update_policy_with_file(map_fd, POLICY_FILE_PATH) == 0) {
                std::cout << "Policy updated successfully.\n";
                break; // 성공적으로 업데이트되면 루프를 빠져나옵니다.
            } else {
                std::cerr << "Failed to update policy, waiting to retry.\n";
                cv.wait_for(lock, std::chrono::seconds(3));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception during policy update: " << e.what() << std::endl;
    }

    policy_update_running.store(false);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////
// 진행 상황 콜백 함수
int progress_callback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    if (exiting) {
        return 1; // 0이 아닌 값을 반환하면 전송이 중단됩니다.
    }
    return 0;
}

// Docker 이벤트 콜백 함수
size_t docker_event_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total_size = size * nmemb;
    auto* event_data = static_cast<DockerEventData*>(userdata);

    // 수신된 데이터를 버퍼에 추가
    event_data->buffer.append(ptr, total_size);

    size_t pos = 0;
    while (true) {
        // 버퍼에서 개행 문자 위치 찾기 (JSON 객체는 개행 문자로 구분됨)
        size_t newline_pos = event_data->buffer.find('\n', pos);
        if (newline_pos == std::string::npos) {
            // 완전한 JSON 객체가 아직 없음
            break;
        }

        // JSON 문자열 추출
        std::string json_str = event_data->buffer.substr(pos, newline_pos - pos);
        pos = newline_pos + 1;

        // JSON 파싱
        try {
            json event_json = json::parse(json_str);

            // 이벤트 처리
            std::string action = event_json["Action"];
            std::string type = event_json["Type"];
            if (type == "container") {
                // 관심 있는 액션인지 확인
                if (action == "create" || action == "destroy" || action == "stop" || action == "start" || action == "restart") {
                    // 정책 업데이트 호출
                    {
                        std::unique_lock<std::mutex> lock(*event_data->mtx);
                        event_data->cv->notify_one();
                    }

                    std::cout << "Docker event detected: " << action << ", updating policy...\n";
                    update_policy_on_event(map_fd, *event_data->mtx, *event_data->cv);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing Docker event JSON: " << e.what() << std::endl;
        }
    }

    // 처리된 부분을 버퍼에서 제거
    event_data->buffer.erase(0, pos);

    // 종료 플래그 확인
    if (exiting) {
        return 0; // 0을 반환하면 전송이 중단됩니다.
    }

    return total_size;
}

// Docker 이벤트 감지 함수
void monitor_docker_events(std::mutex& mtx, std::condition_variable& cv) {
    std::cout << "Monitoring Docker events...\n";

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL for Docker events." << std::endl;
        return;
    }

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, DOCKER_SOCKET);
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/events");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, docker_event_callback);

    // 진행 상황 콜백 설정
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L); // 진행 상황 콜백 활성화

    // 사용자 데이터 설정
    DockerEventData event_data = { &mtx, &cv, "" };
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &event_data);

    // 전송 시작 (한 번만 호출)
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK && res != CURLE_ABORTED_BY_CALLBACK) {
        std::cerr << "CURL Error: " << curl_easy_strerror(res) << std::endl;
    }

    curl_easy_cleanup(curl);
    std::cerr << "Docker event monitoring thread exited.\n";
}

void monitor_policy_file(std::mutex& mtx, std::condition_variable& cv) {
    std::cout << "Monitoring policy file for changes...\n";

    int inotify_fd = inotify_init1(IN_NONBLOCK); // IN_NONBLOCK 플래그 사용
    if (inotify_fd < 0) {
        std::cerr << "Failed to initialize inotify: " << strerror(errno) << std::endl;
        return;
    }

    // 파일 경로와 이름 분리
    std::string file_path = POLICY_FILE_PATH;
    size_t last_slash = file_path.find_last_of('/');
    std::string dir_path = file_path.substr(0, last_slash);
    std::string file_name = file_path.substr(last_slash + 1);

    // 디렉토리를 감시
    // uint32_t watch_events = IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB |
    //                         IN_MOVED_TO | IN_CREATE | IN_DELETE |
    //                         IN_DELETE_SELF | IN_MOVE_SELF;

    uint32_t watch_events = IN_CLOSE_WRITE | IN_DELETE;

    int watch_fd = inotify_add_watch(inotify_fd, dir_path.c_str(), watch_events);
    if (watch_fd < 0) {
        std::cerr << "Failed to add inotify watch for " << dir_path
                  << ": " << strerror(errno) << std::endl;
        close(inotify_fd);
        return;
    }

    std::cout << "Watching directory " << dir_path << " for changes to " << file_name << "...\n";

    char buffer[4096]; // 충분히 큰 버퍼 크기 설정

    struct pollfd fds[1];
    fds[0].fd = inotify_fd;
    fds[0].events = POLLIN;

    while (!exiting) {
        int poll_num = poll(fds, 1, 1000); // 타임아웃을 1초로 설정
        if (poll_num == -1) {
            if (errno == EINTR)
                continue;
            std::cerr << "Poll error: " << strerror(errno) << std::endl;
            break;
        } else if (poll_num == 0) {
            // 타임아웃 발생, 'exiting' 조건 확인
            continue;
        }

        if (fds[0].revents & POLLIN) {
            int length = read(inotify_fd, buffer, sizeof(buffer));
            if (length < 0) {
                if (errno == EAGAIN)
                    continue;
                std::cerr << "Error reading inotify events: " << strerror(errno) << std::endl;
                break;
            } else if (length == 0) {
                // EOF 처리
                continue;
            }

            int i = 0;
            while (i < length) {
                struct inotify_event *event = (struct inotify_event *)&buffer[i];

                // 관심 있는 파일인지 확인
                if (event->len > 0 && file_name == event->name) {
                    uint32_t mask = event->mask;

                    // 디버깅을 위한 이벤트 정보 출력
                    std::cout << "Event mask: " << mask << " on file: " << event->name << std::endl;

                    if (mask & (IN_CLOSE_WRITE | IN_CREATE)) {
                        // 파일이 수정되거나 생성됨
                        std::unique_lock<std::mutex> lock(mtx);
                        cv.notify_one();
                        lock.unlock();

                        std::cout << "File change detected, updating policy...\n";
                        update_policy_on_event(map_fd, mtx, cv);
                    }

                    if (mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                        std::cout << "File was deleted or moved: " << event->name << std::endl;
                        update_policy_on_event(map_fd, mtx, cv);
                    }
                }

                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    inotify_rm_watch(inotify_fd, watch_fd);
    close(inotify_fd);
    std::cerr << "File monitoring thread exited.\n";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////


// 메뉴 옵션을 위한 열거형
enum view_mode {
    ADD_POLICY = 1,
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

// 메뉴 선택 함수
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

// file_exists 함수 정의 추가
bool file_exists(const char *path) {
    struct stat buffer;
    return stat(path, &buffer) == 0;
}

// 메인 함수
int main(int argc, char **argv) {
    struct enforcement_bpf *skel = nullptr;
    struct ring_buffer *rb = nullptr;

    int status = 0;


    env::getEnv();

    std::mutex mtx;
    std::condition_variable cv;

    std::thread file_monitor_thread;
    std::thread docker_event_thread;

    try {
        libbpf_set_print(libbpf_print_fn);
        bump_memlock_rlimit();

        skel = enforcement_bpf__open();
        if (!skel) throw std::runtime_error("Failed to open BPF skeleton");

        int err = enforcement_bpf__load(skel);
        if (err) throw std::runtime_error("Failed to load and verify BPF skeleton");

        err = enforcement_bpf__attach(skel);
        if (err) throw std::runtime_error("Failed to attach BPF skeleton");

        map_fd = bpf_map__fd(skel->maps.policy_map);

        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), print_event, NULL, NULL);
        if (!rb) throw std::runtime_error("Failed to create Ring Buffer");

        if (signal(SIGINT, handle_signal) == SIG_ERR) {
            throw std::runtime_error("Can't set signal handler");
        }

        if (file_exists(POLICY_FILE_PATH)) {
            if (update_policy_with_file(map_fd, POLICY_FILE_PATH) != 0) {
                throw std::runtime_error("Failed to apply initial policy");
            }
        } 
        else {
            // throw std::runtime_error("Policy file not found: " + std::string(POLICY_FILE_PATH));
            std::cerr << "Policy file not found: " << POLICY_FILE_PATH << std::endl;
        }

        file_monitor_thread = std::thread(monitor_policy_file, std::ref(mtx), std::ref(cv));
        docker_event_thread = std::thread(monitor_docker_events, std::ref(mtx), std::ref(cv));

        status = SHOW_LOG;
        while (!exiting) {
            switch (status) {
            case SHOW_LOG:
                err = ring_buffer__poll(rb, 1);
                if (err < 0) throw std::runtime_error("Error polling ring buffer: " + std::to_string(err));
                break;
            default:
                throw std::runtime_error("Unknown status code: " + std::to_string(status));
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    exiting = true;
    if (file_monitor_thread.joinable()) file_monitor_thread.join();
    if (docker_event_thread.joinable()) docker_event_thread.join();
    if (rb) ring_buffer__free(rb);
    if (skel) enforcement_bpf__destroy(skel);

    return 0;
}