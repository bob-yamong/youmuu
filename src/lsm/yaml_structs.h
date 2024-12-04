#pragma once
#ifndef YAML_STRUCTS_H
#define YAML_STRUCTS_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

// Policy 관련 구조체 정의
struct YamlNetworkPolicy {
    std::string ip;
    int port;
    int protocol;
    std::vector<std::string> flags;
    std::vector<int> uid;
};

struct YamlFilePolicy {
    std::string path;
    std::vector<std::string> flags;
    std::vector<int> uid;
};

struct YamlProcessPolicy {
    std::string comm;
    std::vector<std::string> flags;
    std::vector<int> uid;
};

struct YamlLsmPolicy {
    std::vector<YamlFilePolicy> file;
    std::vector<YamlNetworkPolicy> network;
    std::vector<YamlProcessPolicy> process;
};

struct YamlTracepointPolicy {
    std::vector<std::string> syscalls;
};

struct YamlContainerPolicy {
    std::string container_name;
    bool raw_tp_policy;
    YamlLsmPolicy lsm_policies;
    YamlTracepointPolicy tracepoint_policy;
};

struct YamlPolicy {
    std::string api_version;
    std::string name;
    std::vector<YamlContainerPolicy> containers;
};

#endif // YAML_STRUCTS_H