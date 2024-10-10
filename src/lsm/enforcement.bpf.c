#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"

char LICENSE[] SEC("license") = "GPL";


SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    // handle_bprm_check_security(bprm);
	bpf_printk("lsm_hook: exec: bprm_check_security\n");
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
	bpf_printk("lsm_hook: file: file_open\n");
	return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	bpf_printk("lsm_hook: fs: sb_mount\n");
	return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
{
	bpf_printk("lsm_hook: fs: sb_remount\n");
	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
{
	bpf_printk("lsm_hook: fs: sb_umount\n");
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	bpf_printk("lsm_hook: socket: socket_bind\n");
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	bpf_printk("lsm_hook: socket: socket_connect\n");
	return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old,
	 int flags)
{
	bpf_printk("lsm_hook: task: task_fix_setuid\n");
	return 0;
}