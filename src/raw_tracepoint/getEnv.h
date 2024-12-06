// getEnv.h
#ifndef GET_ENV_H
#define GET_ENV_H

#include <string>
#include <stdexcept>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdio>
#include <memory>
#include <array>

class env {
public:
    static std::string cgroup_path;
    static std::string proc_path;
    static std::string log_file_path;

    // static 함수로 변경
    static void getEnv();

    // hostname을 IP로 변환하는 함수 추가
    static std::string resolveHostname(const std::string& hostname);

private:
    static std::string get_env_var(const std::string& var_name);
};

#endif // GET_ENV_H