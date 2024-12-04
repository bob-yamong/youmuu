#include "getEnv.h"

std::string env::cgroup_path;
std::string env::proc_path;
std::string env::kafka_brokers;
std::string env::kafka_topic_tp;
int env::update_interval;
int env::buffer_cnt;

// static 멤버 함수 구현
std::string env::get_env_var(const std::string& var_name, const std::string& default_value) {
    try {
        std::cout << "Getting environment variable: " << var_name << std::endl;
        // 환경변수 값 가져오기 없으면 null return
        const char* val = std::getenv(var_name.c_str());
        // null이면 default_value return 
        if (!val) {
            if (var_name == "KAFKA_BROKERS" || var_name == "KAFKA_TOPIC") {
                std::cerr << "Critical error: Environment variable " << var_name << " is not set." << std::endl;
                exit(EXIT_FAILURE);
            }
            return default_value;
        }
        std::string result = std::string(val);
        std::cout << "Value for " << var_name << ": " << result << std::endl;
        return result;
    } catch (const std::exception& e) {
        std::cerr << "Error getting env var " << var_name << ": " << e.what() << std::endl;
        return default_value;
    }
}

std::string env::resolveHostname(const std::string& hostname) {
    struct addrinfo hints = {}, *result;
    hints.ai_family = AF_UNSPEC;    // IPv4 또는 IPv6 허용
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        throw std::runtime_error("DNS 조회 실패: " + std::string(gai_strerror(status)));
    }

    // 결과 저장을 위한 버퍼
    char ipstr[INET6_ADDRSTRLEN];
    
    // 첫 번째 유효한 주소 사용
    for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
        void* addr;
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        // IP 주소를 문자열로 변환
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        freeaddrinfo(result);
        return std::string(ipstr);
    }

    freeaddrinfo(result);
    throw std::runtime_error("유효한 IP 주소를 찾을 수 없습니다");
}

std::string env::splitHostnamePort(const std::string& hostname) {
    std::vector<std::string> host_port_pairs;
    std::stringstream ss(hostname);
    std::string item;

    // ','를 기준으로 문자열을 분리하여 벡터에 저장
    while (std::getline(ss, item, ',')) {
        host_port_pairs.push_back(item);
    }

    std::vector<std::string> ip_port_pairs;
    for (const auto& host_port : host_port_pairs) {
        std::string host = host_port.substr(0, host_port.find_last_of(":"));
        std::string port = host_port.substr(host_port.find_last_of(":") + 1);
        
        // 호스트 이름이 IP가 아닌 경우에만 IP로 변환
        if (host.find_first_not_of("0123456789.") != std::string::npos) {
            host = resolveHostname(host);
        }
        ip_port_pairs.push_back(host + ":" + port);
    }

    // 벡터를 ','로 연결하여 최종 문자열 생성
    std::string result;
    for (size_t i = 0; i < ip_port_pairs.size(); ++i) {
        result += ip_port_pairs[i];
        if (i < ip_port_pairs.size() - 1) {
            result += ",";
        }
    }

    return result;
}

void env::getEnv() {
    try {
        std::cout << "=== Starting environment initialization ===" << std::endl;

        std::string temp_cgroup = get_env_var("CGROUP_SYSTEM_SLICE_PATH", "/sys/fs/cgroup/system.slice/");
        std::string temp_proc = get_env_var("PROC_PATH", "/proc");
        std::string temp_update_interval = get_env_var("UPDATE_INTERVAL", "60");
        std::string temp_kafka_brokers = splitHostnamePort(get_env_var("KAFKA_BROKERS", ""));
        std::string temp_kafka_topic_tp = get_env_var("KAFKA_TOPIC_TRACEPOINT", "");
        std::string temp_buffer_cnt = get_env_var("BUFFER_CNT", "4");

        kafka_brokers = temp_kafka_brokers;
        kafka_topic_tp = temp_kafka_topic_tp;
        cgroup_path = temp_cgroup;
        proc_path = temp_proc;
        update_interval = std::stoi(temp_update_interval);
        buffer_cnt = std::stoi(temp_buffer_cnt);

    } catch (const std::exception& e) {
        std::cerr << "Critical error in getEnv: " << e.what() << std::endl;
        throw;
    }
}