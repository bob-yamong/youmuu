// getEnv.h
#ifndef GET_ENV_H
#define GET_ENV_H

#include <string>
#include <cstdlib>
#include <stdexcept>

class env {
public:
    static std::string host;
    static std::string dbname;
    static std::string user;
    static std::string password;
    static std::string port;
    static std::string cgroup_path;

    // static 함수로 변경
    static void getEnv();

private:
    static std::string get_env_var(const std::string& var_name);
};

#endif // GET_ENV_H