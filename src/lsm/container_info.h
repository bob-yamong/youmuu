#pragma once
#ifndef CONTAINER_INFO_H
#define CONTAINER_INFO_H

#include <string>
#include <vector>
#include <curl/curl.h>
#include <json-c/json.h>
#include <glob.h>
#include <sys/stat.h>
#include <limits.h>
#include <iostream>
#include <memory>
#include <algorithm>
#include <regex>

#include "getEnv.h"

#define DOCKER_SOCKET "/var/run/docker.sock"

#include "yaml_structs.h"


struct ContainerInfo {
    std::string id;
    std::string name; // 컨테이너 이름 추가
    int pid;
    unsigned long cgroup_id;

    YamlLsmPolicy lsm_policies;

    bool operator==(const ContainerInfo& other) const {
        return id == other.id &&
               name == other.name &&
               pid == other.pid &&
               cgroup_id == other.cgroup_id;
    }
};

class ContainerManager {
public:
    static std::vector<ContainerInfo> containers;
    static std::vector<std::string> monitored_containers; // 모니터링할 컨테이너 이름 리스트 추가
    static YamlPolicy parsed_policy;

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *str);
    static int getContainerPIDs();
    static void getContainerInode(const std::string &container_id);

    // 모니터링 대상 확인 함수 선언 추가
    static std::vector<std::string> isMonitored(const std::string& name);
};

#endif // CONTAINER_INFO_H