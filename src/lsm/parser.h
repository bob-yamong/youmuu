#pragma once
#ifndef PARSER_H
#define PARSER_H

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


std::map<std::string, __u32> flags_map = {
    {"POLICY_AUDIT", POLICY_AUDIT},
    {"POLICY_DENY", POLICY_DENY},
    {"POLICY_ALLOW", POLICY_ALLOW},
    {"POLICY_OWNER", POLICY_OWNER},
    {"POLICY_RECURSIVE", POLICY_RECURSIVE},
    {"POLICY_FILE_READ", POLICY_FILE_READ},
    {"POLICY_FILE_WRITE", POLICY_FILE_WRITE},
    {"POLICY_FILE_CREATE",POLICY_FILE_CREATE},
    {"POLICY_FILE_EXEC", POLICY_FILE_EXEC},
    {"POLICY_FILE_APPEND", POLICY_FILE_APPEND},
    {"POLICY_FILE_RENAME", POLICY_FILE_RENAME},
    {"POLICY_FILE_DELETE", POLICY_FILE_DELETE},
    {"POLICY_NET_CONNECT", POLICY_NET_CONNECT},
    {"POLICY_NET_SRC", POLICY_NET_SRC},
    {"POLICY_NET_DST", POLICY_NET_DST},
    {"POLICY_PROC_FORK", POLICY_PROC_FORK},
    {"POLICY_PROC_EXEC", POLICY_PROC_EXEC},
    {"POLICY_PROC_KILL", POLICY_PROC_KILL},
    {"POLICY_PROC_SETUID", POLICY_PROC_SETUID}
};

__u32 string_to_flags(std::vector<std::string> str_flags){
    __u32 flags = 0;

    for (const auto& str_flag : str_flags) {
        flags |= flags_map[str_flag];
    }

    return flags;
}


std::vector<std::string> flags_to_string(__u32 flags){
    std::vector<std::string> flags_str;

    for (const auto& flag : flags_map) {
        if (flags & flag.second) {
            flags_str.push_back(flag.first);
        }
    }

    return flags_str;
}

// IP 주소와 서브넷 마스크를 저장하는 구조체
struct IpAddress {
    uint32_t ip;
    uint32_t subnet_mask;
};


// IP 주소 문자열을 정수로 변환하는 함수
IpAddress parse_ip(const std::string& ip_str) {
    IpAddress result = {0, 0};
    
    size_t slash_pos = ip_str.find('/');
    std::string ip_part = ip_str.substr(0, slash_pos);
    
    inet_pton(AF_INET, ip_part.c_str(), &result.ip);
    result.ip = ntohl(result.ip);
    
    if (slash_pos != std::string::npos) {
        int prefix_len = stoi(ip_str.substr(slash_pos + 1));
        if (prefix_len >= 0 && prefix_len <= 32) {
            result.subnet_mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
        }
    } else {
        result.subnet_mask = ~0U;
    }
    
    return result;
}


#endif