#ifndef CONTAINER_PID_ID_H
#define CONTAINER_PID_ID_H

#include <linux/types.h>
#include <unordered_map>
#include <string>

extern std::unordered_map<__u32, std::string> pid_namespace_to_container_id;

#endif