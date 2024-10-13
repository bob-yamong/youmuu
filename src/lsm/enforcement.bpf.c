#include "shared.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";


SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    bpf_printk("lsm_hook: exec: bprm_check_security\n");
    
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_BPRM_CHECK_SECURITY;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
	bpf_printk("lsm_hook: file: file_open\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_FILE_OPEN;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	bpf_printk("lsm_hook: fs: sb_mount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_SB_MOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_remount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_SB_REMOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
	bpf_printk("lsm_hook: fs: sb_umount\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_SB_UMOUNT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	bpf_printk("lsm_hook: socket: socket_bind\n");
	
	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_SOCKET_BIND;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	bpf_printk("lsm_hook: socket: socket_connect\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_SOCKET_CONNECT;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old,
	 int flags)
{
	bpf_printk("lsm_hook: task: task_fix_setuid\n");

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->event_id = SECID_TASK_FIX_SETUID;
    e->retval = 0; 
    
    bpf_ringbuf_submit(e, 0);

	return 0;
}