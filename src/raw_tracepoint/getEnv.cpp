// getEnv.cpp
#include "getEnv.h"

// static 멤버 변수 정의
std::string env::host;
std::string env::dbname;
std::string env::user;
std::string env::password;
std::string env::port;
std::string env::cgroup_path;

// static 멤버 함수 구현
std::string env::get_env_var(const std::string& var_name) {
    const char* val = std::getenv(var_name.c_str());
    if (val == nullptr) {
        throw std::runtime_error("환경 변수 " + var_name + "이(가) 설정되지 않았습니다.");
    }
    return std::string(val);
}

void env::getEnv() {
    host = get_env_var("POSTGRES_HOST");
    dbname = get_env_var("POSTGRES_DB");
    user = get_env_var("POSTGRES_USER");
    password = get_env_var("POSTGRES_PASSWORD");
    port = get_env_var("POSTGRES_PORT");
    cgroup_path = get_env_var("CGROUP_SYSTEM_SLICE_PATH");
}