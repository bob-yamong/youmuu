#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <arpa/inet.h>
#include <yaml.h>
#include <cstring>
#include <sstream>
#include <algorithm>

using namespace std;

// IP 주소와 서브넷 마스크를 저장하는 구조체
struct IpAddress {
    uint32_t ip;
    uint32_t subnet_mask;
};

// Policy 관련 구조체 정의
struct NetworkPolicy {
    IpAddress ip_info;
    int port;
    int protocol;
    uint32_t flags;
    vector<int> uid;
};

struct FilePolicy {
    string path;
    uint32_t flags;
    vector<int> uid;
};

struct ProcessPolicy {
    string comm;
    uint32_t flags;
    vector<int> uid;
};

struct ContainerPolicy {
    string container_name;
    vector<FilePolicy> file_policies;
    vector<NetworkPolicy> network_policies;
    vector<ProcessPolicy> process_policies;
};

struct Policy {
    string name;
    vector<ContainerPolicy> containers;
};

// IP 주소 문자열을 정수로 변환하는 함수
IpAddress parseIpAddress(const string& ip_str) {
    IpAddress result = {0, 0};
    
    size_t slash_pos = ip_str.find('/');
    string ip_part = ip_str.substr(0, slash_pos);
    
    inet_pton(AF_INET, ip_part.c_str(), &result.ip);
    result.ip = ntohl(result.ip);
    
    if (slash_pos != string::npos) {
        int prefix_len = stoi(ip_str.substr(slash_pos + 1));
        if (prefix_len >= 0 && prefix_len <= 32) {
            result.subnet_mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
        }
    } else {
        result.subnet_mask = ~0U;
    }
    
    return result;
}

// 플래그 문자열을 uint32_t로 변환하는 함수

uint32_t parseFlags(const vector<string>& flag_strings) {
    static const map<string, uint32_t> flag_values = {
        {"POLICY_AUDIT", POLICY_AUDIT},
        {"POLICY_DENY", POLICY_DENY},
        {"POLICY_ALLOW", POLICY_ALLOW},
        {"POLICY_OWNER", POLICY_OWNER},
        {"POLICY_RECURSIVE", POLICY_RECURSIVE},
        {"POLICY_FILE_READ", POLICY_FILE_READ},
        {"POLICY_FILE_WRITE", POLICY_FILE_WRITE},
        {"POLICY_FILE_EXEC", POLICY_FILE_EXEC},
        {"POLICY_FILE_APPEND", POLICY_FILE_APPEND},
        {"POLICY_FILE_RENAME", POLICY_FILE_RENAME},
        {"POLICY_FILE_DELETE", POLICY_FILE_DELETE},
        {"POLICY_NET_CONNECT", POLICY_NET_CONNECT},
        {"POLICY_NET_BIND", POLICY_NET_BIND},
        {"POLICY_NET_ACCEPT", POLICY_NET_ACCEPT},
        {"POLICY_NET_SEND", POLICY_NET_SEND},
        {"POLICY_NET_RECV", POLICY_NET_RECV},
        {"POLICY_PROC_FORK", POLICY_PROC_FORK},
        {"POLICY_PROC_EXEC", POLICY_PROC_EXEC},
        {"POLICY_PROC_KILL", POLICY_PROC_KILL},
        {"POLICY_PROC_PTRACE", POLICY_PROC_PTRACE},
    };
    
    uint32_t flags = static_cast<uint32_t>(0);
    for (const auto& flag_str : flag_strings) {
        auto it = flag_values.find(flag_str);
        if (it != flag_values.end()) {
            flags |= it->second;
        }
    }
    return flags;
}

vector<string> flagsToString(uint64_t flags) {
    static const map<uint32_t, string> flag_names = {
        {POLICY_AUDIT, "POLICY_AUDIT"},
        {POLICY_DENY, "POLICY_DENY"},
        {POLICY_ALLOW, "POLICY_ALLOW"},
        {POLICY_OWNER, "POLICY_OWNER"},
        {POLICY_RECURSIVE, "POLICY_RECURSIVE"},
        {POLICY_FILE_READ, "POLICY_FILE_READ"},
        {POLICY_FILE_WRITE, "POLICY_FILE_WRITE"},
        {POLICY_FILE_EXEC, "POLICY_FILE_EXEC"},
        {POLICY_FILE_APPEND, "POLICY_FILE_APPEND"},
        {POLICY_FILE_RENAME, "POLICY_FILE_RENAME"},
        {POLICY_FILE_DELETE, "POLICY_FILE_DELETE"},
        {POLICY_NET_CONNECT, "POLICY_NET_CONNECT"},
        {POLICY_NET_BIND, "POLICY_NET_BIND"},
        {POLICY_NET_ACCEPT, "POLICY_NET_ACCEPT"},
        {POLICY_NET_SEND, "POLICY_NET_SEND"},
        {POLICY_NET_RECV, "POLICY_NET_RECV"},
        {POLICY_PROC_FORK, "POLICY_PROC_FORK"},
        {POLICY_PROC_EXEC, "POLICY_PROC_EXEC"},
        {POLICY_PROC_KILL, "POLICY_PROC_KILL"},
        {POLICY_PROC_PTRACE, "POLICY_PROC_PTRACE"}
    };
    
    vector<string> result;
    for (const auto& pair : flag_names) {
        if (static_cast<uint32_t>(flags) & static_cast<uint32_t>(pair.first)) {
            result.push_back(pair.second);
        }
    }
    return result;
}

static string get_scalar_value(yaml_event_t& event) {
    return string((char*)event.data.scalar.value, event.data.scalar.length);
}

Policy parseYamlPolicy(const std::string& filename) {
    Policy policy;
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) {
        cerr << "Failed to open file: " << filename << endl;
        return policy;
    }

    yaml_parser_t parser;
    yaml_event_t event;

    if (!yaml_parser_initialize(&parser)) {
        cerr << "Failed to initialize parser" << endl;
        fclose(file);
        return policy;
    }

    yaml_parser_set_input_file(&parser, file);

    vector<string> context;
    ContainerPolicy* current_container = nullptr;
    string current_policy_type;  // file, network, process
    vector<string> current_flags;
    bool in_sequence = false;
    int sequence_depth = 0;

    FilePolicy* current_file_policy = nullptr;
    NetworkPolicy* current_network_policy = nullptr;
    ProcessPolicy* current_process_policy = nullptr;
    string current_field;  // path, ip, port, protocol, flags, uid, comm

    bool parsing = true;
    while (parsing) {
        if (!yaml_parser_parse(&parser, &event)) {
            cerr << "Parser error" << endl;
            break;
        }

        switch (event.type) {
            case YAML_MAPPING_START_EVENT: {
                if (!(context.empty()) && (context.back() == "policies")) {
                    context.push_back("policy_items");
                }
                break;
            }

            case YAML_SEQUENCE_START_EVENT: {
                sequence_depth++;
                in_sequence = true;
                if (current_field == "flags") {
                    current_flags.clear();
                }
                break;
            }

            case YAML_SEQUENCE_END_EVENT: {
                sequence_depth--;
                if (sequence_depth == 0) {
                    in_sequence = false;
                }
                if (current_field == "flags") {
                    uint64_t flags = 0;
                    for (const auto& flag : current_flags) {
                        flags |= static_cast<uint64_t>(parseFlags({flag}));
                    }
                    
                    if (current_file_policy) {
                        current_file_policy->flags = flags;
                    }
                    else if (current_network_policy) {
                        current_network_policy->flags = flags;
                    }
                    else if (current_process_policy) {
                        current_process_policy->flags = flags;
                    }
                    current_flags.clear();
                }
                break;
            }

            case YAML_SCALAR_EVENT: {
                string value = get_scalar_value(event);

                if (value == "path" || value == "ip" || value == "port" || 
                    value == "protocol" || value == "comm" || value == "flags" || 
                    value == "uid") {
                    current_field = value;
                    continue;
                }

                if (value == "name" && context.empty()) {
                    yaml_parser_parse(&parser, &event);
                    policy.name = get_scalar_value(event);
                    continue;
                }
                else if (value == "policys" || value == "containers" || value == "policies") {
                    context.push_back(value);
                    continue;
                }
                else if (value == "container_name") {
                    yaml_parser_parse(&parser, &event);
                    policy.containers.push_back(ContainerPolicy());
                    current_container = &policy.containers.back();
                    current_container->container_name = get_scalar_value(event);
                    continue;
                }

                if (value == "file" || value == "network" || value == "process") {
                    current_policy_type = value;
                    current_file_policy = nullptr;
                    current_network_policy = nullptr;
                    current_process_policy = nullptr;
                    continue;
                }

                if (in_sequence) {
                    if (current_field == "flags") {
                        current_flags.push_back(value);
                        continue;
                    }
                    else if (current_field == "uid") {
                        try {
                            int uid_value = stoi(value);
                            if (current_file_policy) {
                                current_file_policy->uid.push_back(uid_value);
                            }
                            else if (current_network_policy) {
                                current_network_policy->uid.push_back(uid_value);
                            }
                            else if (current_process_policy) {
                                current_process_policy->uid.push_back(uid_value);
                            }
                        } catch (const std::exception& e) {
                            cerr << "Error parsing UID: " << value << endl;
                        }
                        continue;
                    }
                }

                if (!current_container) continue;

                if (current_field == "path" && current_policy_type == "file") {
                    FilePolicy file_policy;
                    file_policy.path = value;
                    current_container->file_policies.push_back(file_policy);
                    current_file_policy = &current_container->file_policies.back();
                    current_network_policy = nullptr;
                    current_process_policy = nullptr;
                }
                else if (current_field == "ip" && current_policy_type == "network") {
                    NetworkPolicy network_policy;
                    network_policy.ip_info = parseIpAddress(value);
                    network_policy.port = 0;
                    network_policy.protocol = 0;
                    current_container->network_policies.push_back(network_policy);
                    current_network_policy = &current_container->network_policies.back();
                    current_file_policy = nullptr;
                    current_process_policy = nullptr;
                }
                else if (current_field == "port" && current_network_policy) {
                    current_network_policy->port = htons(stoi(value));
                }
                else if (current_field == "protocol" && current_network_policy) {
                    current_network_policy->protocol = stoi(value);
                }
                else if (current_field == "comm" && current_policy_type == "process") {
                    ProcessPolicy process_policy;
                    process_policy.comm = value;
                    current_container->process_policies.push_back(process_policy);
                    current_process_policy = &current_container->process_policies.back();
                    current_file_policy = nullptr;
                    current_network_policy = nullptr;
                }
                break;
            }

            case YAML_MAPPING_END_EVENT: {
                if (!context.empty()) {
                    if (context.back() == current_policy_type) {
                        current_file_policy = nullptr;
                        current_network_policy = nullptr;
                        current_process_policy = nullptr;
                        current_policy_type.clear();
                    }
                    context.pop_back();
                }
                break;
            }

            case YAML_STREAM_END_EVENT:
                parsing = false;
                break;

            default:
                break;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);
    return policy;
}

#endif