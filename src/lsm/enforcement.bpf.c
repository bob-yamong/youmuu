#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf_map_structs.h"

#define AF_INET 2    // IPv4
#define AF_INET6 10  // IPv6

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define FMODE_EXEC (1 << 18) 

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    ////bpf_printk("lsm_hook: exec: bprm_check_security\n");
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }
    
    int ret = init_context(e);
    if (ret < 0) goto clear;

    if (bpf_d_path(&bprm->file->f_path, e->data.path, sizeof(e->data.path)) < 0) {
        //bpf_printk("Failed to get file path");
    }

    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_BPRM_CHECK_SECURITY;
    e->retval = 0;
    
    __u32 flags = match_policy(task, POLICY_PROCESS, e->comm);
    // If there is no policy, allow
    if (!flags) goto clear;

    // If you need to explicitly allow (whitelist | access list), it is denied by default.
    __u8 mode = flags & POLICY_ALLOW;
    if (mode) ret = -1;
    // Allow if policy is wrong or blacklist-based (deny list)
    else ret = 0;

    if ((flags & POLICY_PROC_EXEC)||(flags & POLICY_FILE_EXEC)) ret -= 1;
    
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }

    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(&file->f_path, e->data.path, sizeof(e->data.path)) < 0) {
        //bpf_printk("Failed to get file path");
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);

    //bpf_printk("file_open at %s flag is %u and file_flags is %u \n", e->data.path, flags, file->f_flags);
    //if (!flags) goto clear;
    //맵에 해당 경로에 대한 정책이 없으면 플래그가 반환이 안됨, 하지만 이걸 화이트리스트로 하려고하면 플래그가 반환이 안되면 차단을 해야됨.
    //결국 flag는 해당 경로에 대한 체킹포인트가 되는거임. => 화이트 리스트가 반영되는 순간 결국 모든 경로에 대한 후킹 체크는 들어가야함

    ret = 0;
    // __u8 mode = flags & POLICY_ALLOW;
    // if (mode) e->retval = -1;

    //(파일을 생성하면 파일을 생성하는 경로가 아닌 생성되는 파일의 경로이므로 /test에 대해서 파일 작업을 막으려면 /test/filename을 막아야함)
    //r => 블랙리스트
    //w => 화이트리스트, 근데 해당 경로만 허락이 되는게 아닌 recursive하게 선언하면 결국 이것도 마찬가지로 다 됨
    //e => 블랙리스트
    if ((flags & POLICY_FILE_READ) && ((file->f_flags & O_WRONLY) == 0))  {
        //bpf_printk("block read at %s %d \n", e->data.path, flags);
        ret -= 1;
    }
    if ((!flags) && (file->f_flags & (O_WRONLY | O_RDWR))) {
        bpf_printk("block write at %s %d \n", e->data.path, flags);
        ret -= 1;
    }
    else if((flags & POLICY_FILE_WRITE) && (file->f_flags & (O_WRONLY | O_RDWR))) {
        bpf_printk("allow write at %s %d \n", e->data.path, flags);
        ret = 0;
    }
    // if ((flags & POLICY_FILE_WRITE) && (file->f_flags & (O_WRONLY | O_RDWR))) {
    //     //bpf_printk("block write at %s %d \n", e->data.path, flags);
    //     ret -= 1;
    // }
    if ((flags & POLICY_FILE_EXEC) && (file->f_flags & FMODE_EXEC)) {
        //bpf_printk("block execute at %s %d \n", e->data.path, flags);
        ret -= 1;
    }

    e->event_id = SECID_FILE_OPEN;
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;

    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

// SEC("lsm/sb_mount")
// int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
// 	const char *type, unsigned long flags, void *data)
// {
// 	////bpf_printk("lsm_hook: fs: sb_mount\n");

// 	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_MOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

// 	return 0;
// }

// SEC("lsm/sb_remount")
// int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
// {
// 	////bpf_printk("lsm_hook: fs: sb_remount\n");

// 	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_REMOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

// 	return 0;
// }

// SEC("lsm/sb_umount")
// int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
// {
// 	////bpf_printk("lsm_hook: fs: sb_umount\n");

// 	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_UMOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

// 	return 0;
// }

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
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

    __u32 eperm = match_policy(task, POLICY_NETWORK, &net);

    if ((eperm & 0x0140) == (POLICY_NET_CONNECT | POLICY_NET_DST)) {
        e->retval = -1;   
        bpf_ringbuf_submit(e, 0);
        return -1;
    }

    bpf_ringbuf_discard(e, 0);
	return 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    get_process_path(e->data.source, sizeof(e->data.source));
    
    e->event_id = SECID_SOCKET_RECVMSG;

    struct network_policy net = {};
    struct sock *sk;

    // Get the socket from the socket structure
    bpf_probe_read(&sk, sizeof(sk), &sock->sk);

    // Assuming we are using sk_protocol for family detection
    u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    
    // Get source IP and port
    net.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);  // Source IP address
    net.port = BPF_CORE_READ(sk, __sk_common.skc_num);       // Source port

    net.flags = POLICY_NET_CONNECT;

    __u32 eperm = match_policy(task, POLICY_NETWORK, &net);
    
    if ((eperm & 0x00C0) == (POLICY_NET_CONNECT | POLICY_NET_SRC)) {
        e->retval = -1;   
        bpf_ringbuf_submit(e, 0);
        return -1;
    }

    bpf_ringbuf_discard(e, 0);
    return 0;
}

// SEC("lsm/task_fix_setuid")
// int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old,
// 	 int flags)
// {
// 	////bpf_printk("lsm_hook: task: task_fix_setuid\n");

// 	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_TASK_FIX_SETUID;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

// 	return 0;
// }

// SEC("lsm/kernel_module_request")
// int BPF_PROG(kernel_module_request, char *kmod_name)
// {
//     ////bpf_printk("lsm_hook: kernel: kernel_module_request\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_KERNEL_MODULE_REQUEST;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

// 	return 0;
// }

// SEC("lsm/kernel_read_file")
// int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id)
// {
//     ////bpf_printk("lsm_hook: kernel: kernel_read_file\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_KERNEL_READ_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

// SEC("lsm/bprm_creds_from_file")
// int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
// {
//     ////bpf_printk("lsm_hook: exec: bprm_creds_from_file\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_BPRM_CREDS_FROM_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    ////bpf_printk("lsm_hook: file: file_permission\n");
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
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
    
    bpf_ringbuf_discard(e, 0);

    return 0;

}

// SEC("lsm/capable")
// int BPF_PROG(capable, struct task_struct *task, const struct cred *cred, int cap)
// {
//     ////bpf_printk("lsm_hook: task: capable\n");
//     // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_CAPABLE;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

// SEC("lsm/path_mknod")
// int BPF_PROG(path_mknod, struct path *path, umode_t mode, dev_t dev)
// {
//     ////bpf_printk("lsm_hook: fs: path_mknod\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_MKNOD;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

// SEC("lsm/path_rmdir")
// int BPF_PROG(path_rmdir, struct path *path)
// {
//     ////bpf_printk("lsm_hook: fs: path_rmdir\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_RMDIR;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

SEC("lsm/path_unlink")
//삭제는 블랙리스트
int BPF_PROG(path_unlink, struct path *path)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0) {
        //bpf_printk("Failed to get file path");
    }

    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);
    
    //if (!flags) goto clear;

    __u8 allow_mode = flags & POLICY_ALLOW;
    ret = allow_mode ? 1:0;

    if (flags & POLICY_FILE_DELETE) {
        //해당 경로가 선언이 되어있고, 그 플래그가 파일 생성에 대한 플래그가 있을 때
        ret = 0;       
    }else{
        //경로가 선언만 되어있거나, 선언되어있지 않으면 블락
        ret -= 1; 
    }
  
    
    //bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
 
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}


// SEC("lsm/path_symlink")
// int BPF_PROG(path_symlink, struct path *path, struct path *target)
// {
//     ////bpf_printk("lsm_hook: fs: path_symlink\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_SYMLINK;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

SEC("lsm/path_mkdir")
//폴더 생성은 화이트 리스트
int BPF_PROG(path_mkdir, struct path *path, umode_t mode)
{    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);

    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }  

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0) {
        //bpf_printk("Failed to get file path");
    }

    //bpf_printk("lsm_hook: fs: path_mkdir at %s\n",e->data.path);

    __u32 flags = match_policy(task, POLICY_FILE,e->data.path);
    
    //if (!flags) goto clear;

    __u8 allow_mode = flags & POLICY_ALLOW;
    ret = allow_mode ? 1:0;


    if (flags & POLICY_FILE_APPEND) {
        //해당 경로가 선언이 되어있고, 그 플래그가 파일 생성에 대한 플래그가 있을 때
        ret = 0;       
    }else{
        //경로가 선언만 되어있거나, 선언되어있지 않으면 블락
        ret -= 1; 
    }
    //bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
 
    e->retval = ret;
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

    

// SEC("lsm/path_link")
// int BPF_PROG(path_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry)
// {
//     ////bpf_printk("lsm_hook: fs: path_link\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_LINK;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

SEC("lsm/path_rename")
//이름 변경은 화이트 리스트
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
    //인자 잘못 선언되어있던 것 수정, 차후 파일 전체 로직 통합 및 수정 필요

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_monitor(ppid, cgroup_id)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }       
    char path[256];

    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }


   if (bpf_d_path(old_dir, e->data.path, sizeof(e->data.path)) < 0) {   
        //bpf_printk("Failed to get file path");
    }
    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);

    //bpf_printk("lsm_hook: fs: path_rename at %s\n", e->data.path);
    
    //if (!flags) goto clear;

    __u8 allow_mode = flags & POLICY_ALLOW;
    ret = allow_mode ? 1 : 0;


    if (flags & POLICY_FILE_RENAME) {
        //해당 경로가 선언이 되어있고, 그 플래그가 파일 생성에 대한 플래그가 있을 때
        ret = 0;       
    }else{
        //경로가 선언만 되어있거나, 선언되어있지 않으면 블락
        ret -= 1; 
    }
    //bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
    
    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_PATH_RENAME;   
    e->retval = ret;
    
    if (flags & POLICY_AUDIT) bpf_ringbuf_submit(e, 0);
    else goto clear;
    
    return ret;

clear:
    bpf_ringbuf_discard(e, 0);
    return ret;
}

// SEC("lsm/path_chmod")
// int BPF_PROG(path_chmod, struct path *path, umode_t mode)
// {
//     ////bpf_printk("lsm_hook: fs: path_chmod\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_CHMOD;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

// SEC("lsm/path_truncate")
// int BPF_PROG(path_truncate, struct path *path, loff_t length)
// {
//     ////bpf_printk("lsm_hook: fs: path_truncate\n");
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_PATH_TRUNCATE;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }

// SEC("lsm/mmap_file")
// int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
// {
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    
//     __u64 cgroup_id = bpf_get_current_cgroup_id();

//     if (!should_monitor(ppid, cgroup_id)) {
//         return 0;
//     }

//     event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     //bpf_printk("lsm_hook: file: mmap_file\n");
//     if (!e) {
//         bpf_printk("Failed ringbuf_reserve");
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_MMAP_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_discard(e, 0);

//     return 0;

// }
