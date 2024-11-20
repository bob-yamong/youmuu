#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <asm/unistd_64.h>

#include "../include/reflect-cpp/include/rfl/thirdparty/yyjson.h"
#include "../include/reflect-cpp/src/yyjson.c"
#include "../include/reflect-cpp/src/reflectcpp_yaml.cpp"
#include "../include/reflect-cpp/src/reflectcpp.cpp"
#include "../include/reflect-cpp/include/rfl/yaml.hpp"

using namespace std;

// IP 주소와 서브넷 마스크를 저장하는 구조체
struct IpAddress {
    uint32_t ip;
    uint32_t subnet_mask;
};

// Policy 관련 구조체 정의
struct YamlNetworkPolicy {
    string ip;
    int port;
    int protocol;
    vector<string> flags;
    vector<int> uid;
};

struct YamlFilePolicy {
    string path;
    vector<string> flags;
    vector<int> uid;
};

struct YamlProcessPolicy {
    string comm;
    vector<string> flags;
    vector<int> uid;
};

struct YamlLsmPolicy {
    vector<YamlFilePolicy> file;
    vector<YamlNetworkPolicy> network;
    vector<YamlProcessPolicy> process;
};

struct YamlTracepointPolicy {
    vector<string> syscalls;
};

struct YamlContainerPolicy {
    string container_name;
    bool raw_tp_policy;
    YamlLsmPolicy lsm_policies;
    YamlTracepointPolicy tracepoint_policy;
};

struct YamlPolicy {
    string api_version;
    string name;
    vector<YamlContainerPolicy> containers;
};


#endif