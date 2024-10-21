#ifndef CONTAINER_INFO_H
#define CONTAINER_INFO_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <glob.h>
#include <sys/stat.h>
#include <limits.h>

#define MAX_CONTAINERS 1024
#define DOCKER_SOCKET "/var/run/docker.sock"

struct string {
    char *ptr;
    size_t len;
};

struct container_info {
    char id[64];
    int pid;
};

extern struct container_info containers[MAX_CONTAINERS];
extern int container_count;

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = (char *)malloc(s->len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct string *mem = (struct string *)userp;

    char *ptr = (char *)realloc(mem->ptr, mem->len + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        return 0;
    }

    mem->ptr = ptr;
    memcpy(&(mem->ptr[mem->len]), contents, realsize);
    mem->len += realsize;
    mem->ptr[mem->len] = '\0';

    return realsize;
}

int get_container_pids() {
    CURL *curl;
    CURLcode res;
    struct string s;
    init_string(&s);

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
            if (jobj != NULL) {
                container_count = json_object_array_length(jobj);
                for (int i = 0; i < container_count; i++) {
                    json_object *container = json_object_array_get_idx(jobj, i);
                    json_object *id_obj, *state_obj, *pid_obj;
                    if (json_object_object_get_ex(container, "Id", &id_obj) &&
                        json_object_object_get_ex(container, "State", &state_obj)) {
                        if (json_object_object_get_ex(state_obj, "Pid", &pid_obj)) {
                            strncpy(containers[i].id, json_object_get_string(id_obj), sizeof(containers[i].id) - 1);
                            containers[i].pid = json_object_get_int(pid_obj);
                        }
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
    snprintf(pattern, sizeof(pattern), "/sys/fs/cgroup/*/%s", container_id);

    glob_t globbuf;
    struct stat sb;
    unsigned long inode = 0;
    if (glob(pattern, 0, NULL, &globbuf) == 0) {
        if (globbuf.gl_pathc > 0) {
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

#endif // CONTAINER_INFO_H