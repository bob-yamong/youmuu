#include <linux/types.h>
#include <unordered_map>
#include <string>

static std::unordered_map<__u32, std::string> pid_namespace_to_container_id;