#ifndef SYSCALL_LIST_H
#define SYSCALL_LIST_H

#include <sys/syscall.h>

void init_syscall_map(struct raw_tracepoint_bpf *skel)
{
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        // 프로세스/스레드 관리
        { __NR_clone, "clone" },
        { __NR_clone3, "clone3" },
        { __NR_execve, "execve" },
        { __NR_execveat, "execveat" },
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_kill, "kill" },
        { __NR_tkill, "tkill" },
        { __NR_tgkill, "tgkill" },
        { __NR_ptrace, "ptrace" },
        { __NR_sched_yield, "sched_yield" },
        { __NR_sched_setaffinity, "sched_setaffinity" },
        { __NR_sched_getaffinity, "sched_getaffinity" },
        
        // 파일 시스템
        { __NR_open, "open" },
        { __NR_openat, "openat" },
        { __NR_openat2, "openat2" },
        { __NR_close, "close" },
        { __NR_read, "read" },
        { __NR_pread64, "pread64" },
        { __NR_write, "write" },
        { __NR_pwrite64, "pwrite64" },
        { __NR_readv, "readv" },
        { __NR_writev, "writev" },
        { __NR_lseek, "lseek" },
        { __NR_truncate, "truncate" },
        { __NR_ftruncate, "ftruncate" },
        { __NR_creat, "creat" },
        { __NR_link, "link" },
        { __NR_linkat, "linkat" },
        { __NR_symlink, "symlink" },
        { __NR_symlinkat, "symlinkat" },
        { __NR_readlink, "readlink" },
        { __NR_readlinkat, "readlinkat" },
        { __NR_unlink, "unlink" },
        { __NR_unlinkat, "unlinkat" },
        { __NR_rename, "rename" },
        { __NR_renameat, "renameat" },
        { __NR_renameat2, "renameat2" },
        
        // 메모리 관리
        { __NR_brk, "brk" },
        { __NR_mmap, "mmap" },
        { __NR_munmap, "munmap" },
        { __NR_mprotect, "mprotect" },
        { __NR_mremap, "mremap" },
        { __NR_msync, "msync" },
        { __NR_madvise, "madvise" },
        { __NR_mincore, "mincore" },
        { __NR_mlock, "mlock" },
        { __NR_munlock, "munlock" },
        { __NR_mlockall, "mlockall" },
        { __NR_munlockall, "munlockall" },
        
        // 네트워크
        { __NR_socket, "socket" },
        { __NR_socketpair, "socketpair" },
        { __NR_bind, "bind" },
        { __NR_listen, "listen" },
        { __NR_accept, "accept" },
        { __NR_accept4, "accept4" },
        { __NR_connect, "connect" },
        { __NR_getsockname, "getsockname" },
        { __NR_getpeername, "getpeername" },
        { __NR_sendto, "sendto" },
        { __NR_recvfrom, "recvfrom" },
        { __NR_sendmsg, "sendmsg" },
        { __NR_recvmsg, "recvmsg" },
        { __NR_shutdown, "shutdown" },
        { __NR_setsockopt, "setsockopt" },
        { __NR_getsockopt, "getsockopt" },
        
        // IPC
        { __NR_pipe, "pipe" },
        { __NR_pipe2, "pipe2" },
        { __NR_msgget, "msgget" },
        { __NR_msgsnd, "msgsnd" },
        { __NR_msgrcv, "msgrcv" },
        { __NR_msgctl, "msgctl" },
        { __NR_semget, "semget" },
        { __NR_semop, "semop" },
        { __NR_semctl, "semctl" },
        { __NR_shmget, "shmget" },
        { __NR_shmat, "shmat" },
        { __NR_shmctl, "shmctl" },
        { __NR_shmdt, "shmdt" },
        
        // 시그널 처리
        { __NR_signal, "signal" },
        { __NR_sigaction, "sigaction" },
        { __NR_sigprocmask, "sigprocmask" },
        { __NR_sigreturn, "sigreturn" },
        { __NR_rt_sigaction, "rt_sigaction" },
        { __NR_rt_sigprocmask, "rt_sigprocmask" },
        { __NR_rt_sigreturn, "rt_sigreturn" },
        { __NR_pause, "pause" },
        { __NR_sigsuspend, "sigsuspend" },
        
        // 시스템 정보
        { __NR_uname, "uname" },
        { __NR_sysinfo, "sysinfo" },
        { __NR_getrlimit, "getrlimit" },
        { __NR_setrlimit, "setrlimit" },
        { __NR_getrusage, "getrusage" },
        { __NR_times, "times" },
        { __NR_gettimeofday, "gettimeofday" },
        { __NR_settimeofday, "settimeofday" },
        { __NR_clock_gettime, "clock_gettime" },
        { __NR_clock_settime, "clock_settime" },
        { __NR_clock_getres, "clock_getres" },
        
        // 프로세스/사용자 정보
        { __NR_getpid, "getpid" },
        { __NR_getppid, "getppid" },
        { __NR_getuid, "getuid" },
        { __NR_geteuid, "geteuid" },
        { __NR_getgid, "getgid" },
        { __NR_getegid, "getegid" },
        { __NR_setuid, "setuid" },
        { __NR_setgid, "setgid" },
        { __NR_setreuid, "setreuid" },
        { __NR_setregid, "setregid" },
        { __NR_setresuid, "setresuid" },
        { __NR_setresgid, "setresgid" },
        
        // 디렉토리 조작
        { __NR_chdir, "chdir" },
        { __NR_fchdir, "fchdir" },
        { __NR_getcwd, "getcwd" },
        { __NR_mkdir, "mkdir" },
        { __NR_mkdirat, "mkdirat" },
        { __NR_rmdir, "rmdir" },
        { __NR_getdents, "getdents" },
        { __NR_getdents64, "getdents64" },
        
        // 파일 속성
        { __NR_stat, "stat" },
        { __NR_fstat, "fstat" },
        { __NR_lstat, "lstat" },
        { __NR_access, "access" },
        { __NR_faccessat, "faccessat" },
        { __NR_chmod, "chmod" },
        { __NR_fchmod, "fchmod" },
        { __NR_fchmodat, "fchmodat" },
        { __NR_chown, "chown" },
        { __NR_fchown, "fchown" },
        { __NR_lchown, "lchown" },
        { __NR_fchownat, "fchownat" },
        { __NR_utime, "utime" },
        { __NR_utimes, "utimes" },
        { __NR_futimesat, "futimesat" },
        { __NR_utimensat, "utimensat" },

        // 기타 시스템 조작
        { __NR_ioctl, "ioctl" },
        { __NR_fcntl, "fcntl" },
        { __NR_fsync, "fsync" },
        { __NR_fdatasync, "fdatasync" },
        { __NR_sync, "sync" },
        { __NR_mount, "mount" },
        { __NR_umount2, "umount2" },
        { __NR_pivot_root, "pivot_root" },
        { __NR_syslog, "syslog" },
        { __NR_acct, "acct" },
        { __NR_personality, "personality" },
        { __NR_prctl, "prctl" },
        { __NR_arch_prctl, "arch_prctl" },
        { __NR_quotactl, "quotactl" },
        { __NR_setxattr, "setxattr" },
        { __NR_lsetxattr, "lsetxattr" },
        { __NR_fsetxattr, "fsetxattr" },
        { __NR_getxattr, "getxattr" },
        { __NR_lgetxattr, "lgetxattr" },
        { __NR_fgetxattr, "fgetxattr" },
        { __NR_listxattr, "listxattr" },
        { __NR_llistxattr, "llistxattr" },
        { __NR_flistxattr, "flistxattr" },
        { __NR_removexattr, "removexattr" },
        { __NR_lremovexattr, "lremovexattr" },
        { __NR_fremovexattr, "fremovexattr" },

        { __NR_capget, "capget" },
        { __NR_capset, "capset" },
        { __NR_seccomp, "seccomp" },
        { __NR_keyctl, "keyctl" },
        { __NR_add_key, "add_key" },
        { __NR_request_key, "request_key" },

        // 네트워크 관련
        { __NR_sendmmsg, "sendmmsg" },
        { __NR_recvmmsg, "recvmmsg" },
        { __NR_epoll_create, "epoll_create" },
        { __NR_epoll_create1, "epoll_create1" },
        { __NR_epoll_ctl, "epoll_ctl" },
        { __NR_epoll_wait, "epoll_wait" },
        { __NR_epoll_pwait, "epoll_pwait" },

        // 프로세스/스레드 관련
        { __NR_set_tid_address, "set_tid_address" },
        { __NR_futex, "futex" },
        { __NR_sched_setscheduler, "sched_setscheduler" },
        { __NR_sched_getscheduler, "sched_getscheduler" },
        { __NR_sched_setparam, "sched_setparam" },
        { __NR_sched_getparam, "sched_getparam" },
        { __NR_setns, "setns" },
        { __NR_unshare, "unshare" },

        // 파일시스템 관련
        { __NR_statfs, "statfs" },
        { __NR_fstatfs, "fstatfs" },
        { __NR_sync_file_range, "sync_file_range" },
        { __NR_fallocate, "fallocate" },
        { __NR_dup, "dup" },
        { __NR_dup2, "dup2" },
        { __NR_dup3, "dup3" },
        { __NR_inotify_init, "inotify_init" },
        { __NR_inotify_init1, "inotify_init1" },
        { __NR_inotify_add_watch, "inotify_add_watch" },
        { __NR_inotify_rm_watch, "inotify_rm_watch" },

        // 시간 관련
        { __NR_clock_nanosleep, "clock_nanosleep" },
        { __NR_timer_create, "timer_create" },
        { __NR_timer_settime, "timer_settime" },
        { __NR_timer_gettime, "timer_gettime" },
        { __NR_timer_delete, "timer_delete" },

        // 컨테이너/네임스페이스 관련
        { __NR_clone3, "clone3" },
        { __NR_pidfd_open, "pidfd_open" },
        { __NR_pidfd_send_signal, "pidfd_send_signal" },
        { __NR_pidfd_getfd, "pidfd_getfd" },

        // 프로세스/스레드 관련
        { __NR_getcpu, "getcpu" },
        { __NR_sched_setattr, "sched_setattr" },
        { __NR_sched_getattr, "sched_getattr" },
        { __NR_sched_get_priority_max, "sched_get_priority_max" },
        { __NR_sched_get_priority_min, "sched_get_priority_min" },
        { __NR_sched_rr_get_interval, "sched_rr_get_interval" },

        // 메모리 관리 관련
        { __NR_memfd_create, "memfd_create" },
        { __NR_mlock2, "mlock2" },
        { __NR_pkey_mprotect, "pkey_mprotect" },
        { __NR_pkey_alloc, "pkey_alloc" },
        { __NR_pkey_free, "pkey_free" },

        // 파일시스템 관련
        { __NR_name_to_handle_at, "name_to_handle_at" },
        { __NR_open_by_handle_at, "open_by_handle_at" },
        { __NR_syncfs, "syncfs" },
        { __NR_renameat2, "renameat2" },
        { __NR_copy_file_range, "copy_file_range" },

        // 네트워크 관련
        { __NR_socket_accept4, "socket_accept4" },
        { __NR_recvmmsg, "recvmmsg" },
        { __NR_sendmmsg, "sendmmsg" },
        { __NR_setsockopt, "setsockopt" },
        { __NR_getsockopt, "getsockopt" },

        // 보안 관련
        { __NR_landlock_create_ruleset, "landlock_create_ruleset" },
        { __NR_landlock_add_rule, "landlock_add_rule" },
        { __NR_landlock_restrict_self, "landlock_restrict_self" },

        // 시그널 관련
        { __NR_rt_sigqueueinfo, "rt_sigqueueinfo" },
        { __NR_rt_tgsigqueueinfo, "rt_tgsigqueueinfo" },
        { __NR_signalfd, "signalfd" },
        { __NR_signalfd4, "signalfd4" },

        // IO 관련
        { __NR_io_uring_setup, "io_uring_setup" },
        { __NR_io_uring_enter, "io_uring_enter" },
        { __NR_io_uring_register, "io_uring_register" },

        // 시스템 관련
        { __NR_kexec_load, "kexec_load" },
        { __NR_kexec_file_load, "kexec_file_load" },
        { __NR_init_module, "init_module" },
        { __NR_finit_module, "finit_module" },
        { __NR_delete_module, "delete_module" },

        // 시스템 제어 관련
        { __NR_reboot, "reboot" },
        { __NR_sysctl, "sysctl" },
        { __NR_adjtimex, "adjtimex" },
        { __NR_ntp_adjtime, "ntp_adjtime" },
        { __NR_swapon, "swapon" },
        { __NR_swapoff, "swapoff" },

        // 확장 파일시스템 기능
        { __NR_fanotify_init, "fanotify_init" },
        { __NR_fanotify_mark, "fanotify_mark" },
        { __NR_splice, "splice" },
        { __NR_tee, "tee" },
        { __NR_vmsplice, "vmsplice" },
        { __NR_readahead, "readahead" },
        { __NR_fadvise64, "fadvise64" },

        // 고급 IPC
        { __NR_process_vm_readv, "process_vm_readv" },
        { __NR_process_vm_writev, "process_vm_writev" },
        { __NR_mq_open, "mq_open" },
        { __NR_mq_unlink, "mq_unlink" },
        { __NR_mq_timedsend, "mq_timedsend" },
        { __NR_mq_timedreceive, "mq_timedreceive" },
        { __NR_mq_notify, "mq_notify" },
        { __NR_mq_getsetattr, "mq_getsetattr" },

        // 네임스페이스/컨테이너
        { __NR_setdomainname, "setdomainname" },
        { __NR_sethostname, "sethostname" },
        { __NR_bpf, "bpf" },
        { __NR_userfaultfd, "userfaultfd" },

        // 성능 모니터링
        { __NR_perf_event_open, "perf_event_open" },
        { __NR_sysfs, "sysfs" },
        { __NR_name_to_handle_at, "name_to_handle_at" },
        { __NR_open_by_handle_at, "open_by_handle_at" },

        // 기타 고급 기능
        { __NR_kcmp, "kcmp" },
        { __NR_finit_module, "finit_module" },
        { __NR_seccomp, "seccomp" },
        { __NR_getrandom, "getrandom" },
        { __NR_membarrier, "membarrier" },
        { __NR_rseq, "rseq" }
    };

    for (size_t i = 0; i < sizeof(syscall_list) / sizeof(syscall_list[0]); i++) {
        int key = syscall_list[i].nr;
        char value[16] = {0};
        strncpy(value, syscall_list[i].name, sizeof(value) - 1);
        bpf_map__update_elem(skel->maps.syscall_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    }
}

#endif // SYSCALL_LIST_H