#include "getEnv.h"

// static 멤버 변수 정의
// std::string env::host;
// std::string env::dbname;
// std::string env::user;
// std::string env::password;
// std::string env::port;
std::string env::cgroup_path;
std::string env::proc_path;
int env::update_interval;

// static 멤버 함수 구현
std::string env::get_env_var(const std::string& var_name, const std::string& default_value) {
    try {
        std::cout << "Getting environment variable: " << var_name << std::endl;
        // 환경변수 값 가져오기 없으면 null return
        const char* val = std::getenv(var_name.c_str());
        // null이면 default_value return 
        std::string result = val ? std::string(val) : default_value;
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

void env::getEnv() {
    try {
        std::cout << "=== Starting environment initialization ===" << std::endl;

        // // 임시 변수에 저장 후 멤버 변수에 할당
        // std::string temp_host = get_env_var("POSTGRES_HOST", "0.0.0.0");
        // std::string temp_dbname = get_env_var("POSTGRES_DB", "yamong_postgres");
        // std::string temp_user = get_env_var("POSTGRES_USER", "temp_admin");
        // std::string temp_password = get_env_var("POSTGRES_PASSWORD", "temp_password");
        // std::string temp_port = get_env_var("POSTGRES_PORT", "5432");
        std::string temp_cgroup = get_env_var("CGROUP_SYSTEM_SLICE_PATH", "/sys/fs/cgroup/system.slice/");
        std::string temp_proc = get_env_var("PROC_PATH", "/proc");
        std::string temp_update_interval = get_env_var("UPDATE_INTERVAL", "60");

        // hostname이 IP가 아닌 경우에만 resolve
        // if (temp_host.find_first_not_of("0123456789.") != std::string::npos) {
        //     host = resolveHostname(temp_host);
        // } else {
        //     host = temp_host;
        // }

        // 멤버 변수에 할당
        // dbname = temp_dbname;
        // user = temp_user;
        // password = temp_password;
        // port = temp_port;
        cgroup_path = temp_cgroup;
        proc_path = temp_proc;
        update_interval = std::stoi(temp_update_interval);

        // std::cout << "=== Environment initialization completed ===" << std::endl;
        // std::cout << "Final values:" << std::endl
        //           << "Host: " << host << std::endl
        //           << "DB: " << dbname << std::endl
        //           << "User: " << user << std::endl
        //           << "Port: " << port << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Critical error in getEnv: " << e.what() << std::endl;
        throw;
    }
}