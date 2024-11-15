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
#include "getEnv.h"

#define DOCKER_SOCKET "/var/run/docker.sock"

struct ContainerInfo {
    std::string id;
    int pid;
};

class ContainerManager {
public:
    static std::vector<ContainerInfo> containers;

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *str);
    static int getContainerPIDs();
    static unsigned long getContainerInode(const std::string &container_id);
};

#endif // CONTAINER_INFO_H