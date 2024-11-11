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

// 프로젝트 관련 헤더
#include "raw_tracepoint.skel.h"
#include "event.h"
#include "container_info.h"
#include "syscall_list.h"
#include "parser.h"
#include "EventLogger.h"
#include "getEnv.h"

#define POLICY_FILE_PATH "/policy/policy.yaml"

// 단일 종료 플래그 사용
static std::atomic<bool> exiting(false);
std::condition_variable cv;
std::mutex cv_m;
struct raw_tracepoint_bpf *skel;

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
void policy_reload_thread(const std::string &yaml_file_path) {
    std::unique_lock<std::mutex> lock(cv_m);
    while (!exiting.load(std::memory_order_relaxed)) {
        if(cv.wait_for(lock, std::chrono::minutes(1), []{ return exiting.load(); })) // 1분에 한번씩 정책을 감지 
            break;

        std::cout << "정책을 재로딩합니다: " << yaml_file_path << "\n";

        bool file_exists = std::filesystem::exists(yaml_file_path);
        if(!file_exists){
            std::cerr << "YAML 정책 파일을 찾을 수 없습니다.\n";
            delete_all_monitoring_map();
            continue;
        }

        // YAML 정책을 업데이트
        int err = update_policy_with_file(const_cast<char*>(yaml_file_path.c_str()));
        if (err < 0) {
            std::cerr << "정책 재로딩에 실패했습니다.\n";
            continue;
        }

        std::cout << "정책이 성공적으로 재로딩되었습니다.\n";
    }
}

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

    try
    {
        // 로그 디렉토리 생성
        system("mkdir -p log");

        env::getEnv();
        
        // 연결 문자열 구성
        std::string dbConnectionStr = "dbname=" + env::dbname +
                                      " user=" + env::user +
                                      " password=" + env::password +
                                      " hostaddr=" + env::host +
                                      " port=" + env::port;

        // EventLogger 객체 생성
        const size_t BUFFER_SIZE = 100000;
        const std::string LOG_FILE_PATH = "log/general.log.gz";
        eventLogger = new EventLogger(BUFFER_SIZE, LOG_FILE_PATH, dbConnectionStr);

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

        // YAML 파일 경로 지정 (예: "policy.yaml")
        std::string yaml_file = POLICY_FILE_PATH;
        bool file_exists = std::filesystem::exists(yaml_file);
        if (file_exists)
        {
            std::cout << "YAML 정책 파일을 발견했습니다. 정책을 업데이트합니다...\n";
            err = update_policy_with_file(const_cast<char*>(yaml_file.c_str()));
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

        // 정책 재적용 쓰레드 시작
        std::thread policy_thread(policy_reload_thread, yaml_file);

        // 메인 루프
        while (!exiting.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // 정책 재적용 스레드 종료
        policy_thread.join();
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
