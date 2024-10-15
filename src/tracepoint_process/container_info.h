#ifndef CONTAINER_INFO_H
#define CONTAINER_INFO_H

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <glob.h>
#include <limits.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>  // bool 타입을 사용하기 위해 추가


#define DOCKER_SOCKET "/var/run/docker.sock"
#define MAX_CONTAINERS 100

struct string {
    char *ptr;
    size_t len;
};

struct container_info {
    char id[64];
    int pid;
};

struct container_info containers[MAX_CONTAINERS];
int container_count = 0;

pthread_mutex_t container_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t container_cond = PTHREAD_COND_INITIALIZER;
int container_updated = 0;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct string *mem = (struct string *)userp;

    char *ptr = realloc(mem->ptr, mem->len + realsize + 1);
    if (!ptr) {
        printf("메모리 할당 실패\n");
        return 0;
    }

    mem->ptr = ptr;
    memcpy(&(mem->ptr[mem->len]), contents, realsize);
    mem->len += realsize;
    mem->ptr[mem->len] = 0;

    return realsize;
}

int get_container_pids() {
    CURL *curl;
    CURLcode res;
    struct string s;
    s.len = 0;
    s.ptr = malloc(1);
    s.ptr[0] = '\0';

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, DOCKER_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/containers/json");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&s);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            json_object *jobj = json_tokener_parse(s.ptr);
            if (jobj) {
                int array_len = json_object_array_length(jobj);
                for (int i = 0; i < array_len && i < MAX_CONTAINERS; i++) {
                    json_object *container = json_object_array_get_idx(jobj, i);
                    json_object *id;
                    if (json_object_object_get_ex(container, "Id", &id)) {
                        strncpy(containers[i].id, json_object_get_string(id), sizeof(containers[i].id) - 1);
                        containers[i].id[sizeof(containers[i].id) - 1] = '\0';

                        char inspect_url[256];
                        snprintf(inspect_url, sizeof(inspect_url), "http://localhost/containers/%s/json", containers[i].id);
                        
                        struct string inspect_s;
                        inspect_s.len = 0;
                        inspect_s.ptr = malloc(1);
                        inspect_s.ptr[0] = '\0';

                        curl_easy_setopt(curl, CURLOPT_URL, inspect_url);
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&inspect_s);
                        res = curl_easy_perform(curl);
                        if (res == CURLE_OK) {
                            json_object *inspect_jobj = json_tokener_parse(inspect_s.ptr);
                            if (inspect_jobj) {
                                json_object *state, *pid;
                                if (json_object_object_get_ex(inspect_jobj, "State", &state) &&
                                    json_object_object_get_ex(state, "Pid", &pid)) {
                                    containers[i].pid = json_object_get_int(pid);
                                    container_count++;
                                }
                                json_object_put(inspect_jobj);
                            }
                        }
                        free(inspect_s.ptr);
                    }
                }
                json_object_put(jobj);
            }
        }
        curl_easy_cleanup(curl);
    }
    free(s.ptr);

    return container_count;
}

unsigned long get_container_inode(const char *container_id) {
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "/sys/fs/cgroup/system.slice/docker-%s*", container_id);

    glob_t globbuf;
    unsigned long inode = 0;

    if (glob(pattern, 0, NULL, &globbuf) == 0) {
        if (globbuf.gl_pathc > 0) {
            struct stat sb;
            if (stat(globbuf.gl_pathv[0], &sb) == 0) {
                inode = (unsigned long)sb.st_ino;
            } else {
                fprintf(stderr, "Failed to get inode for container ID: %s\n", container_id);
            }
        } else {
            fprintf(stderr, "No matching files for container ID: %s\n", container_id);
        }
        globfree(&globbuf);
    } else {
        fprintf(stderr, "Failed to perform glob for pattern: %s\n", pattern);
    }

    return inode;
}


#endif