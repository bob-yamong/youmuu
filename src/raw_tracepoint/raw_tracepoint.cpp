// SPDX-License-Identifier: GPL-2.0
#include <iostream>         // cout, cerr 사용
#include <mutex>           // mutex, condition_variable 사용
#include <thread>          // thread 생성 및 관리
#include <vector>          // ContainerManager::containers 사용
#include <signal.h>        // 시그널 핸들링
#include <unistd.h>        // 시스템 콜 관련
#include <string>          // 문자열 처리
#include <atomic>          // atomic 변수 사용
#include <condition_variable> // condition_variable 사용
#include <bpf/libbpf.h>    // BPF 관련
#include <filesystem>      // 파일 존재 확인
#include <algorithm>       // std::find 사용
#include <regex>           // 정규표현식 사용
#include <sys/stat.h>      // stat 사용
#include <curl/curl.h>     // curl 사용
#include <json-c/json.h>   // json-c 사용
#include <glob.h>          // glob 사용
#include <sys/socket.h>    // AF_UNIX 사용
#include <sys/un.h>        // sockaddr_un 사용
#include <sys/types.h>     // stat 사용
#include <sys/inotify.h>   // inotify 사용
#include <poll.h>          // poll 사용
#include <nlohmann/json.hpp> // json 사용

// 프로젝트 관련 헤더
#include "raw_tracepoint.skel.h"
#include "event.h"
#include "container_info.h"
#include "syscall_list.h"
#include "parser.h"
#include "EventLogger.h"
#include "getEnv.h"
#include "yaml_structs.h"

#define POLICY_FILE_PATH "/policy/policy.yaml"

using json = nlohmann::json;

// 단일 종료 플래그 사용
std::atomic<bool> exiting(false);
std::atomic<bool> policy_update_running(false);

std::condition_variable cv;
std::mutex cv_m;
struct raw_tracepoint_bpf *skel;
int inotify_fd = -1;

// debug value
int rb_cnt_1 = 0;
u_int64_t err_cnt = 0;

// 전역 EventLogger 포인터 선언
EventLogger* eventLogger = nullptr;

// 환경 변수 읽기 유틸리티 함수 (main.cpp 내에 정의할 수도 있음)
std::string get_env_var(const std::string& var_name) {
    const char* val = std::getenv(var_name.c_str());
    if (val == nullptr) {
        throw std::runtime_error("환경 변수 " + var_name + "이(가) 설정되지 않았습니다.");
    }
    return std::string(val);
}

int delete_all_monitoring_map() {
    for(const auto &container : ContainerManager::containers){
        __u32 key_pid = static_cast<__u32>(container.pid);
        __u64 key_inode = static_cast<__u64>(container.cgroup_id);
        bpf_map__delete_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), BPF_ANY);
        bpf_map__delete_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), BPF_ANY);
    }
    ContainerManager::containers.clear();
    std::cout << "모니터링 맵을 초기화에 완료했습니다." << std::endl;
    return 0;
}

int update_monitoring_map() {
    std::vector<ContainerInfo> temp_containers = ContainerManager::containers;
    ContainerManager::containers.clear();

    // 모니터링할 컨테이너 PID 가져오기
    int detected_containers = ContainerManager::getContainerPIDs();
    if (detected_containers <= 0) {
        std::cerr << "모니터링할 컨테이너를 찾을 수 없습니다.\n";
        return -1;
    }
    std::cout << detected_containers << "개의 컨테이너를 모니터링합니다.\n";

    for(const auto &container : ContainerManager::containers){
        ContainerManager::getContainerInode(container.id);
    }

    // 컨테이너 정책에서 제거된 목록 map에서 제거 
    for(const auto &container : temp_containers){
        if(std::find(ContainerManager::containers.begin(), ContainerManager::containers.end(), container) == ContainerManager::containers.end()){
            __u32 key_pid = static_cast<__u32>(container.pid);
            __u64 key_inode = static_cast<__u64>(container.cgroup_id);
            bpf_map__delete_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), BPF_ANY);
            bpf_map__delete_elem(skel->maps.container_cgroup_id, &key_inode, sizeof(key_inode), BPF_ANY);
        }
    }

    // 컨테이너 PID를 BPF 맵에 추가
    for (const auto &container : ContainerManager::containers) {
        __u32 key_pid = static_cast<__u32>(container.pid);
        __u32 value_pid = 1;
        __u64 key_inode = static_cast<__u64>(container.cgroup_id);
        __u64 value_inode = 1;

        int err = bpf_map__update_elem(skel->maps.container_pids, &key_pid, sizeof(key_pid), &value_pid, sizeof(value_pid), BPF_ANY);
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

        std::cout << "컨테이너 ID: " << container.id << ", 이름: " << container.name << ", PID: " << container.pid << ", inode: " << key_inode << "를 모니터링 중\n";
    }
    return 0;
}

int update_policy_with_file(char* abs_file_name) {
    // YAML 파일에서 정책 로드
    const rfl::Result<YamlPolicy> result = rfl::yaml::load<YamlPolicy>(abs_file_name);
    if (!result) {
        std::cerr << "Failed to load YAML policy: " << std::endl;
        return -1;
    }
    YamlPolicy policy = result.value();

    // raw_tp_policy가 true인 컨테이너 이름을 리스트에 저장
    ContainerManager::monitored_containers.clear(); // 기존 리스트 초기화
    for (const auto& item : policy.containers) { // YamlPolicy 구조에 따라 수정 필요
        if (item.raw_tp_policy) {
            ContainerManager::monitored_containers.push_back(item.container_name);
        }
    }
    update_monitoring_map();

    return 0;
}

// 정책 업데이트 함수
void update_policy_on_event(std::mutex& mtx, std::condition_variable& cv) {
    if (policy_update_running.exchange(true)) {
        std::cerr << "Policy update already in progress, skipping.\n";
        return;
    }

    try {
        std::unique_lock<std::mutex> lock(mtx);

        while (true) {
            if (update_policy_with_file(POLICY_FILE_PATH) == 0) {
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
                    update_policy_on_event(*event_data->mtx, *event_data->cv);
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
                        update_policy_on_event(mtx, cv);
                    }

                    if (mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                        std::cout << "File was deleted or moved: " << event->name << std::endl;
                        update_policy_on_event(mtx, cv);
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

// 이벤트 핸들러 대신 로그 메시지를 큐에 추가하는 함수
void logging(const struct event& e){
    if (eventLogger) {
        eventLogger->addEvent(e);
    } else {
        std::cerr << "EventLogger가 초기화되지 않았습니다.\n";
    }
}

// 링버퍼 핸들러1
static int handle_event1(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = static_cast<const struct event *>(data);
    rb_cnt_1++;
    if (rb_cnt_1 % 100000 == 0)
        std::cout << "handle_event1 호출됨: cnt=" << e->cnt << ", syscall_nr=" << e->syscall_nr << "\n";
    if(err_cnt != e->error_cnt){
        err_cnt = e->error_cnt;
        std::cout << "Error count: " << err_cnt << "\n";
    }
    // 로그 이벤트를 EventLogger에 추가
    logging(*e);

    return 0;
}

// 링버퍼 소비 스레드 함수
void ringbuf_thread_func(struct ring_buffer *rb)
{
    while (!exiting.load(std::memory_order_relaxed))
    {
        int err = ring_buffer__poll(rb, 1);
        if (err == -EINTR)
        {
            break;
        }
        if (err < 0)
        {
            std::cerr << "Error polling ring buffer: " << err << "\n";
            break;
        }
    }
}

// 정책을 주기적으로 재적용하는 쓰레드 함수
// void policy_reload_thread(const std::string &yaml_file_path) {
//     std::unique_lock<std::mutex> lock(cv_m);
//     while (!exiting.load(std::memory_order_relaxed)) {
//         if(cv.wait_for(lock, std::chrono::seconds(env::update_interval), []{ return exiting.load(); })) // 1분에 한번씩 정책을 감지 
//             break;

//         std::cout << "정책을 재로딩합니다: " << yaml_file_path << "\n";

//         bool file_exists = std::filesystem::exists(yaml_file_path);
//         if(!file_exists){
//             std::cerr << "YAML 정책 파일을 찾을 수 없습니다.\n";
//             delete_all_monitoring_map();
//             continue;
//         }

//         // YAML 정책을 업데이트
//         int err = update_policy_with_file(const_cast<char*>(yaml_file_path.c_str()));
//         if (err < 0) {
//             std::cerr << "정책 재로딩에 실패했습니다.\n";
//             continue;
//         }

//         std::cout << "정책이 성공적으로 재로딩되었습니다.\n";
//     }
// }

// 시그널 핸들러
void sig_handler(int signum) {
    if (signum == SIGINT) {
        exiting.store(true);
        cv.notify_all();
    }
}

int main(int argc, char **argv)
{
    int err;
    // 시그널 핸들러 등록
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    std::thread file_monitor_thread;
    std::thread docker_event_thread;

    try
    {
        env::getEnv();

        // EventLogger 객체 생성
        const size_t BUFFER_SIZE = 100000;
        const std::string LOG_FILE_PATH = env::log_file_path;
        eventLogger = new EventLogger(BUFFER_SIZE, LOG_FILE_PATH);

        // BPF 애플리케이션 로드 및 검증
        skel = raw_tracepoint_bpf__open_and_load();
        if (!skel)
        {
            std::cerr << "Failed to load BPF skeleton.\n";
            delete eventLogger;
            return 1;
        }

        // BPF 프로그램 연결
        err = raw_tracepoint_bpf__attach(skel);
        if (err)
        {
            std::cerr << "Failed to attach BPF skeleton.\n";
            raw_tracepoint_bpf__destroy(skel);
            delete eventLogger;
            return 1;
        }

        std::cout << "BPF 프로그램을 성공적으로 시작했습니다! 프로세스 모니터링을 시작합니다...\n";

        bool file_exists = std::filesystem::exists(POLICY_FILE_PATH);
        if (file_exists)
        {
            std::cout << "YAML 정책 파일을 발견했습니다. 정책을 업데이트합니다...\n";
            err = update_policy_with_file(POLICY_FILE_PATH);
            if (err < 0)
            {
                std::cerr << "YAML 정책 파일을 처리하는데 실패했습니다. 정책이 파일이 감지되면 다시 모니터링을 재개합니다.\n";
                ContainerManager::monitored_containers.clear();
            }
            else
            {
                std::cout << "YAML 정책에 따라 컨테이너를 모니터링 합니다.\n";
            }
        }
        else
        {
            std::cout << "YAML 정책 파일이 존재하지 않습니다. 정책이 파일이 감지되면 다시 모니터링을 재개합니다.\n";
            ContainerManager::monitored_containers.clear(); 
        }

        init_syscall_map(skel);

        // 링버퍼 설정
        struct ring_buffer *rb1 = ring_buffer__new(bpf_map__fd(skel->maps.events_1), handle_event1, NULL, NULL);
        if (!rb1)
        {
            std::cerr << "Failed to create ring buffer\n";
            raw_tracepoint_bpf__destroy(skel);
            delete eventLogger;
            return 1;
        }

        std::cout << "링버퍼 설정 완료\n";

        // 링버퍼 읽기 스레드 생성
        std::thread ringbuf_thread1(ringbuf_thread_func, rb1);

        file_monitor_thread = std::thread(monitor_policy_file, std::ref(cv_m), std::ref(cv));
        docker_event_thread = std::thread(monitor_docker_events, std::ref(cv_m), std::ref(cv));

        // 메인 루프
        while (!exiting.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        exiting = true;
        if (file_monitor_thread.joinable()) file_monitor_thread.join();
        if (docker_event_thread.joinable()) docker_event_thread.join();
        // 링버퍼 읽기 스레드 종료
        ringbuf_thread1.join();

        // 링버퍼 정리
        ring_buffer__free(rb1);

        // BPF 스켈레톤 정리
        raw_tracepoint_bpf__destroy(skel);

        // EventLogger 객체 정리
        if (eventLogger) {
            delete eventLogger;
            eventLogger = nullptr;
        }
    }
    catch (const std::bad_alloc &e)
    {
        std::cerr << "Memory allocation failed: " << e.what() << "\n";
        if (skel)
            raw_tracepoint_bpf__destroy(skel);
        if (eventLogger)
            delete eventLogger;
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        if (skel)
            raw_tracepoint_bpf__destroy(skel);
        if (eventLogger)
            delete eventLogger;
        return 1;
    }

    return err < 0 ? -err : 0;
}