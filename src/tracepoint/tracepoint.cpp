#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <chrono>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nlohmann/json.hpp>
#include <utility>
#include <iostream>
#include <set>
#include <atomic>
#include <condition_variable>
#include <sys/inotify.h>
#include <poll.h>

#include "getEnv.h"
#include "tracepoint.skel.h"
#include "struct.h"
#include "handler.h"
#include "parser.h"
#include "EventLogger.h"
#include "yaml_structs.h"
#include "container_info.h"

#define MAX_PATH 256
#define MAX_SYSCALL_NR 548
#define POLICY_FILE_PATH const_cast<char *>("/policy/policy.yaml")

// 전역 EventLogger 포인터 선언
EventLogger *eventLogger = nullptr;
// 전역으로 모니터링하고 있는 컨테이너 네임스페이스 id 추적
std::set<__u32> current_monitored_namespaces;

struct tracepoint_bpf *skel;

std::atomic<bool> exiting(false);
std::atomic<bool> policy_update_running(false);

int inotify_fd = -1;

using json = nlohmann::json;

void sig_handler(int signal)
{
    if (signal == SIGINT)
    {
        std::cerr << "\nSIGINT received, exiting...\n";
        exiting.store(true);
        close(inotify_fd);
    }
}

int clear_syscall_array_entry(struct bpf_map *syscall_array, __u32 pid_namespace)
{
    __s32 empty_syscalls[120];
    for (int i = 0; i < 120; i++)
    {
        empty_syscalls[i] = -1;
    }

    int err = bpf_map__update_elem(syscall_array, &pid_namespace, sizeof(pid_namespace),
                                   empty_syscalls, sizeof(empty_syscalls), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "Failed to clear syscall array for namespace: %u\n", pid_namespace);
        return -1;
    }
    return 0;
}

int clear_all_policies(struct bpf_map *syscall_array)
{
    int err = 0;
    for (const auto &namespace_id : current_monitored_namespaces)
    {
        if (clear_syscall_array_entry(syscall_array, namespace_id) != 0)
        {
            err = -1;
            fprintf(stderr, "Failed to clear policy for namespace: %u\n", namespace_id);
        }
        else
        {
            printf("Cleared policy for namespace: %u\n", namespace_id);
        }
    }
    current_monitored_namespaces.clear();
    ContainerManager::containers.clear();
    ContainerManager::monitored_containers.clear();
    return err;
}

__u32 get_namespace_id(int container_pid)
{
    char path[MAX_PATH];

    std::string full_path = env::proc_path + "/" + std::to_string(container_pid) + "/ns/pid";
    snprintf(path, sizeof(path), "%s", full_path.c_str());

    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        perror("Failed to open namespace file");
        return 1;
    }

    char link_target[MAX_PATH];
    ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
    if (len < 0)
    {
        perror("Failed to read link");
        close(fd);
        return 1;
    }
    link_target[len] = '\0';

    __u32 ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1)
    {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 1;
    }

    printf("PID namespace ID for PID %d: %u\n", container_pid, ns_id);

    close(fd);
    return ns_id;
}

static time_t get_boot_time()
{
    struct sysinfo si;
    if (sysinfo(&si) != 0)
    {
        fprintf(stderr, "Error getting system info\n");
        return -1;
    }
    time_t current_time = time(NULL);
    return current_time - si.uptime;
}

int update_policy_with_file(struct bpf_map *syscall_array, char *abs_file_name)
{
    int err;
    const rfl::Result<YamlPolicy> result = rfl::yaml::load<YamlPolicy>(abs_file_name);
    YamlPolicy policy = result.value();

    if (policy.containers.empty())
    {
        fprintf(stderr, "No policy found in the file. Clearing all existing policies.\n");
        return clear_all_policies(syscall_array);
    }

    ContainerManager::parsed_policy = policy;

    ContainerManager::monitored_containers.clear(); // 기존 리스트 초기화
    ContainerManager::containers.clear();           // 기존 리스트 초기화

    for (const auto &item : policy.containers)
    { // YamlPolicy 구조에 따라 수정 필요
        ContainerManager::monitored_containers.push_back(item.container_name);
    }
    // 모니터링할 컨테이너 PID 가져오기
    int detected_containers = ContainerManager::getContainerPIDs();
    if (detected_containers <= 0)
    {
        std::cerr << "Can not found container for monitoring.\n";
        return -1;
    }

    // 새로운 정책에 포함된 네임스페이스들을 추적하기 위한 set
    std::set<__u32> new_namespaces;

    for (const auto &container : ContainerManager::containers)
    {
        vector<int> syscall_list = string_to_syscalls(container.tp_policies.syscalls);

        syscall_list.erase(
            std::remove_if(syscall_list.begin(), syscall_list.end(),
                           [](int syscall)
                           { return syscall == -1; }),
            syscall_list.end());

        if (syscall_list.size() > 120)
        {
            fprintf(stderr, "Warning: Container %s has more than 120 syscalls. Only first 120 will be monitored.\n",
                    container.name.c_str());
            syscall_list.resize(120);
        }

        ContainerManager::updateContainerNsId(container.id, get_namespace_id(container.pid));

        // 새로운 네임스페이스 추가
        new_namespaces.insert(container.ns_id);

        __s32 syscalls[120];
        for (int i = 0; i < 120; i++)
        {
            syscalls[i] = -1;
        }
        for (size_t i = 0; i < syscall_list.size(); i++)
        {
            syscalls[i] = syscall_list[i];
        }

        // 맵 업데이트
        err = bpf_map__update_elem(syscall_array, &container.ns_id, sizeof(container.ns_id),
                                   syscalls, sizeof(syscalls), BPF_ANY);
        if (err)
        {
            fprintf(stderr, "Failed to update syscall array for container: %s\n", container.id.c_str());
            continue;
        }

        printf("Updated policy for container %s: monitoring %zu syscalls\n",
               container.name.c_str(), syscall_list.size());
    }

    // 이전에 모니터링하던 네임스페이스 중 새로운 정책에 없는 것들을 찾아서 제거
    for (const auto &old_namespace : current_monitored_namespaces)
    {
        if (new_namespaces.find(old_namespace) == new_namespaces.end())
        {
            // 새로운 정책에 없는 네임스페이스의 정책을 제거
            err = clear_syscall_array_entry(syscall_array, old_namespace);
            if (err)
            {
                fprintf(stderr, "Failed to remove old policy for namespace: %u\n", old_namespace);
            }
            else
            {
                printf("Removed policy for namespace: %u\n", old_namespace);
            }
        }
    }

    // 현재 모니터링 중인 네임스페이스 목록 업데이트
    current_monitored_namespaces = new_namespaces;

    return 0;
}

bool file_exists(const char *file_path)
{
    struct stat buffer;
    return stat(file_path, &buffer) == 0;
}

void update_policy_on_event(struct bpf_map *syscall_array, std::mutex &mtx, std::condition_variable &cv)
{
    if (policy_update_running.exchange(true))
    {
        std::cerr << "Policy update already in progress, skipping.\n";
        return;
    }

    try
    {
        std::unique_lock<std::mutex> lock(mtx);

        while (true)
        {
            // 종료 신호가 들어왔다면 즉시 탈출
            if (exiting)
            {
                std::cerr << "Exiting signaled, aborting policy update.\n";
                break;
            }

            // 정책 업데이트 시도
            if (update_policy_with_file(syscall_array, POLICY_FILE_PATH) == 0)
            {
                std::cout << "Policy updated successfully.\n";
                break; // 성공 시 루프 종료
            }
            else
            {
                std::cerr << "Failed to update policy, waiting to retry.\n";

                // 3초 대기 중에 종료 신호가 오거나, notify_one()이 호출될 수 있음
                // wait_for에서 깨어난 뒤 다시 exiting 상태를 확인
                cv.wait_for(lock, std::chrono::seconds(3));

                if (exiting)
                {
                    std::cerr << "Exiting signaled during policy update wait, aborting.\n";
                    break;
                }

                // 여기서 다시 루프 처음으로 돌아가서 update_policy_with_file 시도
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception during policy update: " << e.what() << std::endl;
    }

    policy_update_running.store(false);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
// 진행 상황 콜백 함수
int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    if (exiting)
    {
        return 1; // 0이 아닌 값을 반환하면 전송이 중단됩니다.
    }
    return 0;
}

// Docker 이벤트 콜백 함수
size_t docker_event_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total_size = size * nmemb;
    auto *event_data = static_cast<DockerEventData *>(userdata);

    // 수신된 데이터를 버퍼에 추가
    event_data->buffer.append(ptr, total_size);

    size_t pos = 0;
    while (true)
    {
        // 버퍼에서 개행 문자 위치 찾기 (JSON 객체는 개행 문자로 구분됨)
        size_t newline_pos = event_data->buffer.find('\n', pos);
        if (newline_pos == std::string::npos)
        {
            // 완전한 JSON 객체가 아직 없음
            break;
        }

        // JSON 문자열 추출
        std::string json_str = event_data->buffer.substr(pos, newline_pos - pos);
        pos = newline_pos + 1;

        // JSON 파싱
        try
        {
            json event_json = json::parse(json_str);

            // 이벤트 처리
            std::string action = event_json["Action"];
            std::string type = event_json["Type"];
            if (type == "container")
            {
                // 관심 있는 액션인지 확인
                // action == "create" || 
                if (action == "destroy" || action == "stop" || action == "start" || action == "restart")
                {
                    // 정책 업데이트 호출
                    {
                        std::unique_lock<std::mutex> lock(*event_data->mtx);
                        event_data->cv->notify_one();
                    }

                    std::cout << "Docker event detected: " << action << ", updating policy...\n";
                    update_policy_on_event(skel->maps.syscall_array, *event_data->mtx, *event_data->cv);
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error parsing Docker event JSON: " << e.what() << std::endl;
        }
    }

    // 처리된 부분을 버퍼에서 제거
    event_data->buffer.erase(0, pos);

    // 종료 플래그 확인
    if (exiting)
    {
        return 0; // 0을 반환하면 전송이 중단됩니다.
    }

    return total_size;
}

// Docker 이벤트 감지 함수
void monitor_docker_events(std::mutex &mtx, std::condition_variable &cv)
{
    std::cout << "Monitoring Docker events...\n";

    CURL *curl = curl_easy_init();
    if (!curl)
    {
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
    DockerEventData event_data = {&mtx, &cv, ""};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &event_data);

    // 전송 시작 (한 번만 호출)
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK && res != CURLE_ABORTED_BY_CALLBACK)
    {
        std::cerr << "CURL Error: " << curl_easy_strerror(res) << std::endl;
    }

    curl_easy_cleanup(curl);
    std::cerr << "Docker event monitoring thread exited.\n";
}

void monitor_policy_file(std::mutex &mtx, std::condition_variable &cv)
{
    std::cout << "Monitoring policy file for changes...\n";

    int inotify_fd = inotify_init1(IN_NONBLOCK); // IN_NONBLOCK 플래그 사용
    if (inotify_fd < 0)
    {
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
    if (watch_fd < 0)
    {
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

    while (!exiting)
    {
        int poll_num = poll(fds, 1, 1000); // 타임아웃을 1초로 설정
        if (poll_num == -1)
        {
            if (errno == EINTR)
                continue;
            std::cerr << "Poll error: " << strerror(errno) << std::endl;
            break;
        }
        else if (poll_num == 0)
        {
            // 타임아웃 발생, 'exiting' 조건 확인
            continue;
        }

        if (fds[0].revents & POLLIN)
        {
            int length = read(inotify_fd, buffer, sizeof(buffer));
            if (length < 0)
            {
                if (errno == EAGAIN)
                    continue;
                std::cerr << "Error reading inotify events: " << strerror(errno) << std::endl;
                break;
            }
            else if (length == 0)
            {
                // EOF 처리
                continue;
            }

            int i = 0;
            while (i < length)
            {
                struct inotify_event *event = (struct inotify_event *)&buffer[i];

                // 관심 있는 파일인지 확인
                if (event->len > 0 && file_name == event->name)
                {
                    uint32_t mask = event->mask;

                    // 디버깅을 위한 이벤트 정보 출력
                    std::cout << "Event mask: " << mask << " on file: " << event->name << std::endl;

                    if (mask & (IN_CLOSE_WRITE | IN_CREATE))
                    {
                        // 파일이 수정되거나 생성됨
                        std::unique_lock<std::mutex> lock(mtx);
                        cv.notify_one();
                        lock.unlock();

                        std::cout << "File change detected, updating policy...\n";
                        update_policy_on_event(skel->maps.syscall_array, mtx, cv);
                    }

                    if (mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF))
                    {
                        std::cout << "File was deleted or moved: " << event->name << std::endl;
                        update_policy_on_event(skel->maps.syscall_array, mtx, cv);
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

int main(int argc, char **argv) 
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct ring_buffer *rb = nullptr;
    int err = 0;

    std::mutex mtx;
    std::condition_variable cv;

    std::thread file_monitor_thread;
    std::thread docker_event_thread;

    try {
        env::getEnv();

        // EventLogger 객체 생성
        eventLogger = new EventLogger(env::buffer_cnt, env::kafka_brokers, env::kafka_topic_tp);
        if (!eventLogger) {
            std::cerr << "Failed to create EventLogger" << std::endl;
            throw std::runtime_error("Failed to create EventLogger");
        }

        boot_time = get_boot_time();
        if (boot_time == -1) {
            fprintf(stderr, "Failed to get boot time\n");
            throw std::runtime_error("Failed to get boot time");
        }

        init_event_handlers();
        skel = tracepoint_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open and load BPF skeleton\n");
            throw std::runtime_error("Failed to open BPF skeleton");
        }

        err = tracepoint_bpf__load(skel);
        if (err) {
            fprintf(stderr, "Failed to load and verify BPF skeleton\n");
            throw std::runtime_error("Failed to load and verify BPF skeleton");
        }

        err = tracepoint_bpf__attach(skel);
        if (err) {
            fprintf(stderr, "Failed to attach BPF skeleton\n");
            throw std::runtime_error("Failed to attach BPF skeleton");
        }

        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            throw std::runtime_error("Failed to create ring buffer");
        }

        printf("Successfully started!\n");

        if (file_exists(POLICY_FILE_PATH)) {
            if (update_policy_with_file(skel->maps.syscall_array, POLICY_FILE_PATH) != 0) {
                std::cerr << "Failed to apply initial policy" << std::endl;
            }
        } else {
            std::cerr << "Policy file not found: " << POLICY_FILE_PATH << std::endl;
        }

        file_monitor_thread = std::thread(monitor_policy_file, std::ref(mtx), std::ref(cv));
        docker_event_thread = std::thread(monitor_docker_events, std::ref(mtx), std::ref(cv));

        while (!exiting) {
            err = ring_buffer__poll(rb, 100);
            if (err == -EINTR) {
                printf("\nExiting...\n");
                break;
            } else if (err < 0) {
                printf("Error polling ring buffer: %d\n", err);
                break;
            }
        }

    } catch (const std::exception &ex) {
        std::cerr << "Exception occurred: " << ex.what() << std::endl;
        err = 1;
    } catch (...) {
        std::cerr << "Unknown exception occurred." << std::endl;
        err = 1;
    }

    // 스레드 join
    if (file_monitor_thread.joinable()) file_monitor_thread.join();
    if (docker_event_thread.joinable()) docker_event_thread.join();

    // 리소스 정리
    delete eventLogger;
    eventLogger = nullptr;

    if (rb)
        ring_buffer__free(rb);
    if (skel)
        tracepoint_bpf__destroy(skel);

    return err != 0;
}