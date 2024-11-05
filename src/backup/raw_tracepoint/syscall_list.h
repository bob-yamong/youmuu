#ifndef SYSCALL_LIST_H
#define SYSCALL_LIST_H

#include <sys/syscall.h>

void init_syscall_map(struct raw_tracepoint_bpf *skel)
{
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        // 프로세스 관련
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_kill, "kill" },
        { __NR_tkill, "tkill" },
        { __NR_tgkill, "tgkill" },
        { __NR_ptrace, "ptrace" },
        { __NR_setpgid, "setpgid" },
        { __NR_setsid, "setsid" },
        { __NR_setuid, "setuid" },
        { __NR_setgid, "setgid" },
        { __NR_setreuid, "setreuid" },
        { __NR_setregid, "setregid" },
        { __NR_setresuid, "setresuid" },
        { __NR_setresgid, "setresgid" },
        { __NR_setgroups, "setgroups" },
        { __NR_prctl, "prctl" },
        { __NR_capset, "capset" },
        { __NR_setpriority, "setpriority" },
        { __NR_sched_setscheduler, "sched_setscheduler" },
        { __NR_sched_setparam, "sched_setparam" },
        { __NR_sched_setaffinity, "sched_setaffinity" },
        { __NR_sched_yield, "sched_yield" },

        // 파일 시스템 관련
        { __NR_open, "open" },
        { __NR_openat, "openat" },
        { __NR_close, "close" },
        { __NR_read, "read" },
        { __NR_write, "write" },
        { __NR_lseek, "lseek" },
        { __NR_unlink, "unlink" },
        { __NR_rename, "rename" },
        { __NR_mkdir, "mkdir" },
        { __NR_rmdir, "rmdir" },
        { __NR_chdir, "chdir" },
        { __NR_chmod, "chmod" },
        { __NR_chown, "chown" },
        { __NR_mount, "mount" },
        { __NR_umount2, "umount2" },

        // 네트워크 관련
        { __NR_socket, "socket" },
        { __NR_connect, "connect" },
        { __NR_accept, "accept" },
        { __NR_bind, "bind" },
        { __NR_listen, "listen" },
        { __NR_sendto, "sendto" },
        { __NR_recvfrom, "recvfrom" },
        { __NR_setsockopt, "setsockopt" },
        { __NR_getsockopt, "getsockopt" },
        // 기타 시스템 콜 추가
        { __NR_brk, "brk" },
        { __NR_munmap, "munmap" },
        { __NR_mprotect, "mprotect" },
        { __NR_mmap, "mmap" },
        { __NR_mremap, "mremap" },
        { __NR_getpid, "getpid" },
        { __NR_getppid, "getppid" },
        { __NR_getuid, "getuid" },
        { __NR_geteuid, "geteuid" },
        { __NR_getgid, "getgid" },
        { __NR_getegid, "getegid" },
        { __NR_times, "times" },
        { __NR_nanosleep, "nanosleep" },
        { __NR_clock_gettime, "clock_gettime" },
        { __NR_gettimeofday, "gettimeofday" },
        { __NR_settimeofday, "settimeofday" },
        { __NR_getrlimit, "getrlimit" },
        { __NR_setrlimit, "setrlimit" },
        { __NR_sysinfo, "sysinfo" },
        { __NR_getdents, "getdents" },
        { __NR_fstat, "fstat" },
        { __NR_stat, "stat" },
        { __NR_lstat, "lstat" },
        { __NR_pipe, "pipe" },
        { __NR_pipe2, "pipe2" },
        { __NR_dup, "dup" },
        { __NR_dup2, "dup2" },
        { __NR_dup3, "dup3" },
        { __NR_ioctl, "ioctl" },
        { __NR_fcntl, "fcntl" },
        { __NR_fsync, "fsync" },
        { __NR_fdatasync, "fdatasync" },
        { __NR_sync, "sync" },
        { __NR_syncfs, "syncfs" }
    };

    for (size_t i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
        int key = syscall_list[i].nr;
        char value[16] = {0};  // 16바이트 버퍼 생성
        strncpy(value, syscall_list[i].name, sizeof(value) - 1); 
        bpf_map__update_elem(skel->maps.syscall_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    }
}

#endif // SYSCALL_LIST_H