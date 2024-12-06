#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <asm/unistd_64.h>
#include <arpa/inet.h>

#include "../include/reflect-cpp/include/rfl/thirdparty/yyjson.h"
#include "../include/reflect-cpp/src/yyjson.c"
#include "../include/reflect-cpp/src/reflectcpp_yaml.cpp"
#include "../include/reflect-cpp/src/reflectcpp.cpp"
#include "../include/reflect-cpp/include/rfl/yaml.hpp"

#include "yaml_structs.h"

struct DockerEventData {
    std::mutex* mtx;
    std::condition_variable* cv;
    std::string buffer; // 수신된 데이터를 누적할 버퍼
};

// IP 주소와 서브넷 마스크를 저장하는 구조체
struct IpAddress {
    uint32_t ip;
    uint32_t subnet_mask;
};

#endif