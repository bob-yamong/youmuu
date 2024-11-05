#ifndef CONTAINER_INFO_H
#define CONTAINER_INFO_H

#include <string>
#include <vector>
#include <curl/curl.h>
#include <json-c/json.h>
#include <glob.h>
#include <sys/stat.h>
#include <limits.h>
#include <mutex>
#include <unordered_set>

#define DOCKER_SOCKET "/var/run/docker.sock"
#define MAX_CONTAINERS 100

struct ContainerInfo {
    std::string id;
    std::string name; // 컨테이너 이름 추가
    int pid;
    unsigned long cgroup_id;

    bool operator==(const ContainerInfo& other) const {
        return id == other.id &&
               name == other.name &&
               pid == other.pid &&
               cgroup_id == other.cgroup_id;
    }
};

// 해시 함수: ContainerInfo를 pid로 해싱
struct ContainerInfoHash {
    std::size_t operator()(const ContainerInfo& ci) const {
        return std::hash<int>()(ci.pid);
    }
};

// 비교 함수: pid를 기준으로 동일 여부 판단
struct ContainerInfoEqual {
    bool operator()(const ContainerInfo& a, const ContainerInfo& b) const {
        return a.pid == b.pid;
    }
};

class ContainerManager {
public:
    static std::vector<ContainerInfo> containers;
    static std::vector<std::string> monitored_containers; // 모니터링할 컨테이너 이름 리스트 추가

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *str);
    static int getContainerPIDs();
    static void getContainerInode(const std::string &container_id);
};

#endif // CONTAINER_INFO_H
