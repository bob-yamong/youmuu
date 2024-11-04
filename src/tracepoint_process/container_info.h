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

#define DOCKER_SOCKET "/var/run/docker.sock"
#define MAX_CONTAINERS 100

struct ContainerInfo {
    std::string id;
    std::string name; // 컨테이너 이름 추가
    int pid;
};

class ContainerManager {
public:
    static std::vector<ContainerInfo> containers;
    static std::vector<std::string> monitored_containers; // 모니터링할 컨테이너 이름 리스트 추가

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *str);
    static int getContainerPIDs();
    static unsigned long getContainerInode(const std::string &container_id);
};

#endif // CONTAINER_INFO_H
