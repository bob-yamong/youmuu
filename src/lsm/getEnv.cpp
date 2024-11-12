// getEnv.cpp
#include "getEnv.h"
#include <cstdio>
#include <memory>
#include <array>

// static 멤버 변수 정의
std::string env::host;
std::string env::dbname;
std::string env::user;
std::string env::password;
std::string env::port;
std::string env::cgroup_path;
std::string env::proc_path;

// static 멤버 함수 구현
std::string env::get_env_var(const std::string& var_name) {
    const char* val = std::getenv(var_name.c_str());
    if (val == nullptr) {
        throw std::runtime_error("환경 변수 " + var_name + "이(가) 설정되지 않았습니다.");
    }
    return std::string(val);
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
    std::string hostname = get_env_var("POSTGRES_HOST");
    // hostname이 IP가 아닌 경우에만 resolve
    if (hostname.find_first_not_of("0123456789.") != std::string::npos) {
        host = resolveHostname(hostname);
    } else {
        host = hostname;
    }
    
    dbname = get_env_var("POSTGRES_DB");
    user = get_env_var("POSTGRES_USER");
    password = get_env_var("POSTGRES_PASSWORD");
    port = get_env_var("POSTGRES_PORT");
    cgroup_path = get_env_var("CGROUP_SYSTEM_SLICE_PATH");
    proc_path = get_env_var("PROC_PATH");
}