#include "container_info.h"

// 정적 멤버 초기화
std::vector<ContainerInfo> ContainerManager::containers;
std::vector<std::string> ContainerManager::monitored_containers;
YamlPolicy ContainerManager::parsed_policy;

// isMonitored 함수 수정: 모든 매칭 패턴을 반환
std::vector<std::string> ContainerManager::isMonitored(const std::string& name) {
    std::vector<std::string> matched_patterns;
    for (const auto& pattern : monitored_containers) {
        if (name == pattern) {
            matched_patterns.push_back(pattern);
            continue; // Continue to find other matches
        }
        try {
            std::regex regex_pattern(pattern);
            if (std::regex_match(name, regex_pattern)) {
                matched_patterns.push_back(pattern);
            }
        } catch (const std::regex_error& e) {
            // 패턴이 유효한 정규표현식이 아닌 경우, 무시하고 다음 패턴으로
            std::cerr << "Invalid regex pattern: " << pattern << " Error: " << e.what() << std::endl;
            continue;
        }
    }
    return matched_patterns;
}

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

                    // 모니터링 대상인지 확인: 모든 매칭 패턴 처리
                    std::vector<std::string> matched_patterns = isMonitored(info.name);
                    for (const auto& matched_pattern : matched_patterns) {
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
                                    // 정책에 맞는 lsm_policies 찾기
                                    for (const auto& policy_container : parsed_policy.containers) {
                                        if (policy_container.container_name == matched_pattern) {
                                            info.raw_tp_policy = policy_container.raw_tp_policy;
                                            break;
                                        }
                                    }
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