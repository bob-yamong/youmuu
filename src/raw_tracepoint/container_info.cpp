#include "container_info.h"

// 정적 멤버 초기화
std::vector<ContainerInfo> ContainerManager::containers;
std::vector<std::string> ContainerManager::monitored_containers;

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
                json_object *id_obj, *name_obj;
                if (json_object_object_get_ex(container, "Id", &id_obj) &&
                    json_object_object_get_ex(container, "Names", &name_obj)) {
                    
                    ContainerInfo info;
                    info.id = json_object_get_string(id_obj);

                    // Names는 배열이므로 첫 번째 이름을 사용
                    json_object *name_array = name_obj;
                    if (json_object_array_length(name_array) > 0) {
                        json_object *name = json_object_array_get_idx(name_array, 0);
                        std::string full_name = json_object_get_string(name);
                        // 이름 앞의 '/' 제거
                        if (!full_name.empty() && full_name[0] == '/')
                            info.name = full_name.substr(1);
                        else
                            info.name = full_name;
                    } else {
                        info.name = "unknown";
                    }

                    // 모니터링 대상이 비어있으면 모든 컨테이너 추가
                    // if (monitored_containers.empty()) {
                    //     std::string inspect_url = "http://localhost/containers/" + info.id + "/json";
                    //     std::string inspect_response;
                    //     curl_easy_setopt(curl, CURLOPT_URL, inspect_url.c_str());
                    //     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &inspect_response);
                    //     res = curl_easy_perform(curl);
                    //     if (res == CURLE_OK) {
                    //         json_object *inspect_jobj = json_tokener_parse(inspect_response.c_str());
                    //         if (inspect_jobj) {
                    //             json_object *state_obj, *pid_obj;
                    //             if (json_object_object_get_ex(inspect_jobj, "State", &state_obj) &&
                    //                 json_object_object_get_ex(state_obj, "Pid", &pid_obj)) {
                    //                 info.pid = json_object_get_int(pid_obj);
                    //                 containers.push_back(info);
                    //             }
                    //             json_object_put(inspect_jobj);
                    //         }
                    //     }
                    // }
                    
                    // 모니터링 대상인지 확인
                    if (std::find(monitored_containers.begin(), monitored_containers.end(), info.name) != monitored_containers.end()) {
                        std::string inspect_url = "http://localhost/containers/" + info.id + "/json";
                        std::string inspect_response;
                        curl_easy_setopt(curl, CURLOPT_URL, inspect_url.c_str());
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &inspect_response);
                        res = curl_easy_perform(curl);
                        if (res == CURLE_OK) {
                            json_object *inspect_jobj = json_tokener_parse(inspect_response.c_str());
                            if (inspect_jobj) {
                                json_object *state_obj, *pid_obj;
                                if (json_object_object_get_ex(inspect_jobj, "State", &state_obj) &&
                                    json_object_object_get_ex(state_obj, "Pid", &pid_obj)) {
                                    info.pid = json_object_get_int(pid_obj);
                                    containers.push_back(info);
                                }
                                json_object_put(inspect_jobj);
                            }
                        }
                    }
                    
                }
            }
            json_object_put(jobj);
        }

        curl_easy_cleanup(curl);
    }

    return containers.size();
}

void ContainerManager::getContainerInode(const std::string &container_id) {
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), (env::cgroup_path + "docker-%s*").c_str(), container_id.c_str());

    glob_t globbuf;
    unsigned long inode = 0;

    if (glob(pattern, 0, NULL, &globbuf) == 0) {
        if (globbuf.gl_pathc > 0) {
            struct stat sb;
            if (stat(globbuf.gl_pathv[0], &sb) == 0) {
                inode = sb.st_ino;
                for(auto &container : containers) {
                    if(container.id == container_id) {
                        container.cgroup_id = inode;
                        break;
                    }
                }
            } else {
                std::cerr << "Failed to get inode for container ID: " << container_id << std::endl;
            }
        } else {
            std::cerr << "No matching files for container ID: " << container_id << std::endl;
        }
        globfree(&globbuf);
    } else {
        std::cerr << "Failed to perform glob for pattern: " << pattern << std::endl;
    }
}