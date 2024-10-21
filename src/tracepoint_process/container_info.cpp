#include "container_info.h"
#include <iostream>
#include <memory>

std::vector<ContainerInfo> ContainerManager::containers;

size_t ContainerManager::writeCallback(void *contents, size_t size, size_t nmemb, std::string *str) {
    size_t newLength = size * nmemb;
    try {
        str->append((char*)contents, newLength);
    } catch(std::bad_alloc &e) {
        std::cerr << "Memory allocation failed: " << e.what() << '\n';
        return 0;
    }
    return newLength;
}

int ContainerManager::getContainerPIDs() {
    CURL *curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, DOCKER_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/containers/json");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return 0;
        }

        json_object *jobj = json_tokener_parse(response.c_str());
        if (jobj) {
            int arraylen = json_object_array_length(jobj);
            for (int i = 0; i < arraylen; i++) {
                json_object *container = json_object_array_get_idx(jobj, i);
                json_object *id_obj, *state_obj, *pid_obj;
                if (json_object_object_get_ex(container, "Id", &id_obj) &&
                    json_object_object_get_ex(state_obj, "Pid", &pid_obj)) {
                    ContainerInfo info;
                    info.id = json_object_get_string(id_obj);
                    info.pid = json_object_get_int(pid_obj);
                    containers.push_back(info);
                }
            }
            json_object_put(jobj);
        }

        curl_easy_cleanup(curl);
    }
    return containers.size();
}

unsigned long ContainerManager::getContainerInode(const std::string &container_id) {
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "/sys/fs/cgroup/*/%s", container_id.c_str());

    glob_t globbuf;
    unsigned long inode = 0;
    if (glob(pattern, 0, NULL, &globbuf) == 0) {
        if (globbuf.gl_pathc > 0) {
            struct stat sb;
            if (stat(globbuf.gl_pathv[0], &sb) == 0) {
                inode = sb.st_ino;
            }
        }
        globfree(&globbuf);
    }
    return inode;
}
