#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf_map_structs.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    //bpf_printk("lsm_hook: exec: bprm_check_security\n");
    
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }
    
    int ret = init_context(e);
    if (ret < 0) goto clear;

    if (bpf_d_path(&bprm->file->f_path, e->data.path, sizeof(e->data.path)) < 0) {
        bpf_printk("Failed to get file path");
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_BPRM_CHECK_SECURITY;
    e->retval = 0;
    
    __u32 flags = match_policy(POLICY_PROCESS, e->comm);
    // If there is no policy, allow
    if (!flags) goto clear;

    // If you need to explicitly allow (whitelist | access list), it is denied by default.
    __u8 mode = flags & POLICY_ALLOW;
    if (mode) ret = -1;
    // Allow if policy is wrong or blacklist-based (deny list)
    else ret = 0;

    if (flags & POLICY_PROC_EXEC) ret -= 1;
    
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
	//bpf_printk("lsm_hook: file: file_open\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if(bpf_d_path(&file->f_path, e->data.path, sizeof(e->data.path)) < 0){
        bpf_printk("Failed to get file path");
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    __u32 flags = match_policy(POLICY_FILE, e->data.path);

    // If there is no policy, allow
    if (!flags) goto clear;

    ret = 0;
    // If you need to explicitly allow (whitelist | access list), it is denied by default.
    __u8 mode = flags & POLICY_ALLOW;
    if (mode) e->retval = -1;
    
    if (
        (flags & POLICY_FILE_READ)
        || (flags & POLICY_FILE_WRITE)
        || (flags & POLICY_FILE_EXEC)
    ) ret -= 1;

    e->event_id = SECID_FILE_OPEN;
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;   
clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	//bpf_printk("lsm_hook: fs: sb_mount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_SB_MOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
{
	//bpf_printk("lsm_hook: fs: sb_remount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_SB_REMOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
	//bpf_printk("lsm_hook: fs: sb_umount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_SB_UMOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{

    // __u32 pid_ns_id;
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    // bpf_printk("socket_connect_bpf: pid_ns_id=%u\n", pid_ns_id);

	   event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_SOCKET_CONNECT;


    struct network_policy net = {};
    // Handle IPv4
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        net.ip = addr_in->sin_addr.s_addr;  // Extract IPv4 address (in network byte order)
        net.port = addr_in->sin_port;        // Port is in network byte order
        net.protocol = IPPROTO_TCP;          // Defaulting to TCP; change as necessary for your use case
    } 
    // Handle IPv6
    else if (address->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        // Set IP to 0 or handle accordingly for IPv6
        net.ip = 0;  // This could be adjusted depending on your policy handling needs
        net.port = addr_in6->sin6_port;  // Port is in network byte order
        net.protocol = IPPROTO_IPV6;      // Defaulting to IPv6; change as necessary for your use case
    }

    // Determine the protocol based on the type of socket if needed
    // For example, you might want to set it based on the socket type:
    // - SOCK_STREAM (TCP)
    // - SOCK_DGRAM (UDP)
    switch (sock->type) {
        case SOCK_STREAM:
            net.protocol = IPPROTO_TCP;  // For TCP
            break;
        case SOCK_DGRAM:
            net.protocol = IPPROTO_UDP;   // For UDP
            break;
        // Add other types as necessary, like SOCK_RAW for ICMP
        default:
            net.protocol = IPPROTO_IP;     // Default to IP
            break;
    }

    net.flags = POLICY_NET_CONNECT;

    int eperm = match_policy(POLICY_NETWORK, &net);

    if (eperm != 0) {
        // bpf_printk("Permission denied\n");
        e->retval = -1;   
        bpf_ringbuf_submit(e, 0);
        return -1;
    }

    bpf_ringbuf_discard(e, 0);
	   return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {

    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    

    // int ret = init_context(e);
    // if (ret < 0) {
    //     bpf_ringbuf_discard(e, 0);
    //     return 0;
    // }

    get_process_path(e->data.source, sizeof(e->data.source));
    e->event_id = SECID_XDP;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_ringbuf_discard(e, 0);  // Add discard here
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_ringbuf_discard(e, 0);  // Add discard here
        return XDP_PASS;
    }

    // Variables for IP addresses and protocol
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8 protocol = iph->protocol;

    // Check the protocol and extract port numbers for TCP/UDP
    __u16 src_port = 0, dst_port = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((void *)(tcph + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);  // Add discard here
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((void *)(udph + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);  // Add discard here
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    }

    // Log source and destination IP addresses, protocol, and ports
    bpf_printk("SRC IP: %x, DST IP: %x, PROTOCOL: %d, SRC PORT: %d, DST PORT: %d\n", 
                src_ip, dst_ip, protocol, src_port, dst_port);

    struct network_policy net_src = {};
    struct network_policy net_dst = {};

    net_src.ip = src_ip;
    net_src.port = src_port;
    net_src.protocol = protocol;
    net_src.flags = POLICY_NET_CONNECT;

    net_dst.ip = dst_ip;
    net_dst.port = dst_port;
    net_dst.protocol = protocol;
    net_dst.flags = POLICY_NET_CONNECT;

    int eperm_src = match_policy(POLICY_NETWORK, &net_src);
    int eperm_dst = match_policy(POLICY_NETWORK, &net_dst);

    if (eperm_src == (POLICY_NET_CONNECT | POLICY_NET_SRC) || eperm_dst == (POLICY_NET_CONNECT | POLICY_NET_DST)) {
        e->retval = XDP_DROP;
        bpf_ringbuf_submit(e, 0);  // Submit the event
        return XDP_DROP;
    }

    bpf_ringbuf_discard(e, 0);  // Discard if no block condition is met
    return XDP_PASS;  // Allow the traffic if no block condition is met
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old,
	 int flags)
{
	//bpf_printk("lsm_hook: task: task_fix_setuid\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_TASK_FIX_SETUID;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request, char *kmod_name)
{
    //bpf_printk("lsm_hook: kernel: kernel_module_request\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_KERNEL_MODULE_REQUEST;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id)
{
    //bpf_printk("lsm_hook: kernel: kernel_read_file\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_KERNEL_READ_FILE;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{
    //bpf_printk("lsm_hook: exec: bprm_creds_from_file\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_BPRM_CREDS_FROM_FILE;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    //bpf_printk("lsm_hook: file: file_permission\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    struct dentry *dentry;
    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry) == 0) {
        const unsigned char *name;
        if (bpf_probe_read_kernel(&name, sizeof(name), &dentry->d_name.name) == 0) {
            bpf_probe_read_kernel_str(e->data.path, sizeof(e->data.path), name);
        }
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_FILE_PERMISSION;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/capable")
int BPF_PROG(capable, struct task_struct *task, const struct cred *cred, int cap)
{
    //bpf_printk("lsm_hook: task: capable\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_CAPABLE;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, struct path *path, umode_t mode, dev_t dev)
{
    //bpf_printk("lsm_hook: fs: path_mknod\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_MKNOD;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, struct path *path)
{
    //bpf_printk("lsm_hook: fs: path_rmdir\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_RMDIR;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *path)
{
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0) {
        bpf_printk("Failed to get file path");
    }

    __u32 flags = match_policy(POLICY_FILE, e->data.path);
    
    if (!flags) goto clear;

    __u8 allow_mode = flags & POLICY_ALLOW;
    ret = allow_mode ? 1:0;

    if (flags & POLICY_FILE_DELETE) ret -= 1;       
    
    bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
 
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}


SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, struct path *path, struct path *target)
{
    //bpf_printk("lsm_hook: fs: path_symlink\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_SYMLINK;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, struct path *path, umode_t mode)
{    
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);

    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }  

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0) {
        bpf_printk("Failed to get file path");
    }

    bpf_printk("lsm_hook: fs: path_mkdir at %s\n",e->data.path);

    __u32 flags = match_policy(POLICY_FILE,e->data.path);
    
    if (!flags) goto clear;

    __u8 allow_mode = flags & POLICY_ALLOW;
    ret = allow_mode ? 1:0;

    if (flags & POLICY_FILE_APPEND) ret -= 1;       
    
    bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
 
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

    

SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry)
{
    //bpf_printk("lsm_hook: fs: path_link\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_LINK;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_rename")
int BPF_PROG(path_rename, struct path *old_path, struct path *new_path)
{
    //bpf_printk("lsm_hook: fs: path_rename\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_PATH_RENAME;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, struct path *path, umode_t mode)
{
    //bpf_printk("lsm_hook: fs: path_chmod\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_CHMOD;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, struct path *path, loff_t length)
{
    //bpf_printk("lsm_hook: fs: path_truncate\n");
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Faild ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_PATH_TRUNCATE;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    bpf_printk("lsm_hook: file: mmap_file\n");
        bpf_printk("Faild ringbuf_reserve");
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_MMAP_FILE;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;

}
