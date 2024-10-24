#include "event.h"

#define MAX_EVENTS 4096

struct EventEntry event_table[MAX_EVENTS];

__u32 hash(const char* str) {
    __u32 hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % MAX_EVENTS;
}

void init_event_table() {
    memset(event_table, 0, sizeof(event_table));

    #define ADD_EVENT(name_str, id_val) do { \
        __u32 index = hash(name_str); \
        while (event_table[index].name != NULL) \
            index = (index + 1) % MAX_EVENTS; \
        event_table[index] = (struct EventEntry){.name = name_str, .id = id_val}; \
    } while(0)

    ADD_EVENT("sys_enter_socket", SYS_ENTER_SOCKET);
    ADD_EVENT("sys_exit_socket", SYS_EXIT_SOCKET);
    ADD_EVENT("sys_enter_socketpair", SYS_ENTER_SOCKETPAIR);
    ADD_EVENT("sys_exit_socketpair", SYS_EXIT_SOCKETPAIR);
    ADD_EVENT("sys_enter_setsockopt", SYS_ENTER_SETSOCKOPT);
    ADD_EVENT("sys_exit_setsockopt", SYS_EXIT_SETSOCKOPT);
    ADD_EVENT("sys_enter_getsockopt", SYS_ENTER_GETSOCKOPT);
    ADD_EVENT("sys_exit_getsockopt", SYS_EXIT_GETSOCKOPT);
    ADD_EVENT("sys_enter_getsockname", SYS_ENTER_GETSOCKNAME);
    ADD_EVENT("sys_exit_getsockname", SYS_EXIT_GETSOCKNAME);
    ADD_EVENT("sys_enter_getpeername", SYS_ENTER_GETPEERNAME);
    ADD_EVENT("sys_exit_getpeername", SYS_EXIT_GETPEERNAME);
    ADD_EVENT("sys_enter_bind", SYS_ENTER_BIND);
    ADD_EVENT("sys_exit_bind", SYS_EXIT_BIND);
    ADD_EVENT("sys_enter_listen", SYS_ENTER_LISTEN);
    ADD_EVENT("sys_exit_listen", SYS_EXIT_LISTEN);
    ADD_EVENT("sys_enter_accept", SYS_ENTER_ACCEPT);
    ADD_EVENT("sys_exit_accept", SYS_EXIT_ACCEPT);
    ADD_EVENT("sys_enter_accept4", SYS_ENTER_ACCEPT4);
    ADD_EVENT("sys_exit_accept4", SYS_EXIT_ACCEPT4);
    ADD_EVENT("sys_enter_connect", SYS_ENTER_CONNECT);
    ADD_EVENT("sys_exit_connect", SYS_EXIT_CONNECT);
    ADD_EVENT("sys_enter_shutdown", SYS_ENTER_SHUTDOWN);
    ADD_EVENT("sys_exit_shutdown", SYS_EXIT_SHUTDOWN);
    ADD_EVENT("sys_enter_recvfrom", SYS_ENTER_RECVFROM);
    ADD_EVENT("sys_exit_recvfrom", SYS_EXIT_RECVFROM);
    ADD_EVENT("sys_enter_recvmsg", SYS_ENTER_RECVMSG);
    ADD_EVENT("sys_exit_recvmsg", SYS_EXIT_RECVMSG);
    ADD_EVENT("sys_enter_recvmmsg", SYS_ENTER_RECVMMSG);
    ADD_EVENT("sys_exit_recvmmsg", SYS_EXIT_RECVMMSG);
    ADD_EVENT("sys_enter_sendto", SYS_ENTER_SENDTO);
    ADD_EVENT("sys_exit_sendto", SYS_EXIT_SENDTO);
    ADD_EVENT("sys_enter_sendmsg", SYS_ENTER_SENDMSG);
    ADD_EVENT("sys_exit_sendmsg", SYS_EXIT_SENDMSG);
    ADD_EVENT("sys_enter_sendmmsg", SYS_ENTER_SENDMMSG);
    ADD_EVENT("sys_exit_sendmmsg", SYS_EXIT_SENDMMSG);
    ADD_EVENT("sys_enter_sethostname", SYS_ENTER_SETHOSTNAME);
    ADD_EVENT("sys_exit_sethostname", SYS_EXIT_SETHOSTNAME);
    ADD_EVENT("sys_enter_setdomainname", SYS_ENTER_SETDOMAINNAME);
    ADD_EVENT("sys_exit_setdomainname", SYS_EXIT_SETDOMAINNAME);
    ADD_EVENT("sys_enter_ioctl", SYS_ENTER_IOCTL);
    ADD_EVENT("sys_exit_ioctl", SYS_EXIT_IOCTL);
    ADD_EVENT("sys_enter_poll", SYS_ENTER_POLL);
    ADD_EVENT("sys_exit_poll", SYS_EXIT_POLL);
    ADD_EVENT("sys_enter_ppoll", SYS_ENTER_PPOLL);
    ADD_EVENT("sys_exit_ppoll", SYS_EXIT_PPOLL);
    ADD_EVENT("sys_enter_epoll_create", SYS_ENTER_EPOLL_CREATE);
    ADD_EVENT("sys_exit_epoll_create", SYS_EXIT_EPOLL_CREATE);
    ADD_EVENT("sys_enter_epoll_create1", SYS_ENTER_EPOLL_CREATE1);
    ADD_EVENT("sys_exit_epoll_create1", SYS_EXIT_EPOLL_CREATE1);
    ADD_EVENT("sys_enter_epoll_ctl", SYS_ENTER_EPOLL_CTL);
    ADD_EVENT("sys_exit_epoll_ctl", SYS_EXIT_EPOLL_CTL);
    ADD_EVENT("sys_enter_epoll_wait", SYS_ENTER_EPOLL_WAIT);
    ADD_EVENT("sys_exit_epoll_wait", SYS_EXIT_EPOLL_WAIT);
    ADD_EVENT("sys_enter_epoll_pwait", SYS_ENTER_EPOLL_PWAIT);
    ADD_EVENT("sys_exit_epoll_pwait", SYS_EXIT_EPOLL_PWAIT);
    ADD_EVENT("sys_enter_epoll_pwait2", SYS_ENTER_EPOLL_PWAIT2);
    ADD_EVENT("sys_exit_epoll_pwait2", SYS_EXIT_EPOLL_PWAIT2);
    ADD_EVENT("sys_enter_close", SYS_ENTER_CLOSE);
    ADD_EVENT("sys_exit_close", SYS_EXIT_CLOSE);
    ADD_EVENT("sys_enter_creat", SYS_ENTER_CREAT);
    ADD_EVENT("sys_exit_creat", SYS_EXIT_CREAT);
    ADD_EVENT("sys_enter_open", SYS_ENTER_OPEN);
    ADD_EVENT("sys_exit_open", SYS_EXIT_OPEN);
    ADD_EVENT("sys_enter_openat", SYS_ENTER_OPENAT);
    ADD_EVENT("sys_exit_openat", SYS_EXIT_OPENAT);
    ADD_EVENT("sys_enter_openat2", SYS_ENTER_OPENAT2);
    ADD_EVENT("sys_exit_openat2", SYS_EXIT_OPENAT2);
    ADD_EVENT("sys_enter_name_to_handle_at", SYS_ENTER_NAME_TO_HANDLE_AT);
    ADD_EVENT("sys_exit_name_to_handle_at", SYS_EXIT_NAME_TO_HANDLE_AT);
    ADD_EVENT("sys_enter_open_by_handle_at", SYS_ENTER_OPEN_BY_HANDLE_AT);
    ADD_EVENT("sys_exit_open_by_handle_at", SYS_EXIT_OPEN_BY_HANDLE_AT);
    ADD_EVENT("sys_enter_memfd_create", SYS_ENTER_MEMFD_CREATE);
    ADD_EVENT("sys_exit_memfd_create", SYS_EXIT_MEMFD_CREATE);
    ADD_EVENT("sys_enter_mknod", SYS_ENTER_MKNOD);
    ADD_EVENT("sys_exit_mknod", SYS_EXIT_MKNOD);
    ADD_EVENT("sys_enter_mknodat", SYS_ENTER_MKNODAT);
    ADD_EVENT("sys_exit_mknodat", SYS_EXIT_MKNODAT);
    ADD_EVENT("sys_enter_rename", SYS_ENTER_RENAME);
    ADD_EVENT("sys_exit_rename", SYS_EXIT_RENAME);
    ADD_EVENT("sys_enter_renameat", SYS_ENTER_RENAMEAT);
    ADD_EVENT("sys_exit_renameat", SYS_EXIT_RENAMEAT);
    ADD_EVENT("sys_enter_renameat2", SYS_ENTER_RENAMEAT2);
    ADD_EVENT("sys_exit_renameat2", SYS_EXIT_RENAMEAT2);
    ADD_EVENT("sys_enter_truncate", SYS_ENTER_TRUNCATE);
    ADD_EVENT("sys_exit_truncate", SYS_EXIT_TRUNCATE);
    ADD_EVENT("sys_enter_ftruncate", SYS_ENTER_FTRUNCATE);
    ADD_EVENT("sys_exit_ftruncate", SYS_EXIT_FTRUNCATE);
    ADD_EVENT("sys_enter_fallocate", SYS_ENTER_FALLOCATE);
    ADD_EVENT("sys_exit_fallocate", SYS_EXIT_FALLOCATE);
    ADD_EVENT("sys_enter_mkdir", SYS_ENTER_MKDIR);
    ADD_EVENT("sys_exit_mkdir", SYS_EXIT_MKDIR);
    ADD_EVENT("sys_enter_mkdirat", SYS_ENTER_MKDIRAT);
    ADD_EVENT("sys_exit_mkdirat", SYS_EXIT_MKDIRAT);
    ADD_EVENT("sys_enter_rmdir", SYS_ENTER_RMDIR);
    ADD_EVENT("sys_exit_rmdir", SYS_EXIT_RMDIR);
    ADD_EVENT("sys_enter_getcwd", SYS_ENTER_GETCWD);
    ADD_EVENT("sys_exit_getcwd", SYS_EXIT_GETCWD);
    ADD_EVENT("sys_enter_chdir", SYS_ENTER_CHDIR);
    ADD_EVENT("sys_exit_chdir", SYS_EXIT_CHDIR);
    ADD_EVENT("sys_enter_fchdir", SYS_ENTER_FCHDIR);
    ADD_EVENT("sys_exit_fchdir", SYS_EXIT_FCHDIR);
    ADD_EVENT("sys_enter_chroot", SYS_ENTER_CHROOT);
    ADD_EVENT("sys_exit_chroot", SYS_EXIT_CHROOT);
    ADD_EVENT("sys_enter_pivot_root", SYS_ENTER_PIVOT_ROOT);
    ADD_EVENT("sys_exit_pivot_root", SYS_EXIT_PIVOT_ROOT);
    ADD_EVENT("sys_enter_getdents", SYS_ENTER_GETDENTS);
    ADD_EVENT("sys_exit_getdents", SYS_EXIT_GETDENTS);
    ADD_EVENT("sys_enter_getdents64", SYS_ENTER_GETDENTS64);
    ADD_EVENT("sys_exit_getdents64", SYS_EXIT_GETDENTS64);
    ADD_EVENT("sys_enter_link", SYS_ENTER_LINK);
    ADD_EVENT("sys_exit_link", SYS_EXIT_LINK);
    ADD_EVENT("sys_enter_linkat", SYS_ENTER_LINKAT);
    ADD_EVENT("sys_exit_linkat", SYS_EXIT_LINKAT);
    ADD_EVENT("sys_enter_symlink", SYS_ENTER_SYMLINK);
    ADD_EVENT("sys_exit_symlink", SYS_EXIT_SYMLINK);
    ADD_EVENT("sys_enter_symlinkat", SYS_ENTER_SYMLINKAT);
    ADD_EVENT("sys_exit_symlinkat", SYS_EXIT_SYMLINKAT);
    ADD_EVENT("sys_enter_unlink", SYS_ENTER_UNLINK);
    ADD_EVENT("sys_exit_unlink", SYS_EXIT_UNLINK);
    ADD_EVENT("sys_enter_unlinkat", SYS_ENTER_UNLINKAT);
    ADD_EVENT("sys_exit_unlinkat", SYS_EXIT_UNLINKAT);
    ADD_EVENT("sys_enter_readlink", SYS_ENTER_READLINK);
    ADD_EVENT("sys_exit_readlink", SYS_EXIT_READLINK);
    ADD_EVENT("sys_enter_readlinkat", SYS_ENTER_READLINKAT);
    ADD_EVENT("sys_exit_readlinkat", SYS_EXIT_READLINKAT);
    ADD_EVENT("sys_enter_umask", SYS_ENTER_UMASK);
    ADD_EVENT("sys_exit_umask", SYS_EXIT_UMASK);
    ADD_EVENT("sys_enter_newstat", SYS_ENTER_NEWSTAT);
    ADD_EVENT("sys_exit_newstat", SYS_EXIT_NEWSTAT);
    ADD_EVENT("sys_enter_newlstat", SYS_ENTER_NEWLSTAT);
    ADD_EVENT("sys_exit_newlstat", SYS_EXIT_NEWLSTAT);
    ADD_EVENT("sys_enter_newfstat", SYS_ENTER_NEWFSTAT);
    ADD_EVENT("sys_exit_newfstat", SYS_EXIT_NEWFSTAT);
    ADD_EVENT("sys_enter_newfstatat", SYS_ENTER_NEWFSTATAT);
    ADD_EVENT("sys_exit_newfstatat", SYS_EXIT_NEWFSTATAT);
    ADD_EVENT("sys_enter_statx", SYS_ENTER_STATX);
    ADD_EVENT("sys_exit_statx", SYS_EXIT_STATX);
    ADD_EVENT("sys_enter_statfs", SYS_ENTER_STATFS);
    ADD_EVENT("sys_exit_statfs", SYS_EXIT_STATFS);
    ADD_EVENT("sys_enter_fstatfs", SYS_ENTER_FSTATFS);
    ADD_EVENT("sys_exit_fstatfs", SYS_EXIT_FSTATFS);
    ADD_EVENT("sys_enter_chmod", SYS_ENTER_CHMOD);
    ADD_EVENT("sys_exit_chmod", SYS_EXIT_CHMOD);
    ADD_EVENT("sys_enter_fchmod", SYS_ENTER_FCHMOD);
    ADD_EVENT("sys_exit_fchmod", SYS_EXIT_FCHMOD);
    ADD_EVENT("sys_enter_fchmodat", SYS_ENTER_FCHMODAT);
    ADD_EVENT("sys_exit_fchmodat", SYS_EXIT_FCHMODAT);
    ADD_EVENT("sys_enter_chown", SYS_ENTER_CHOWN);
    ADD_EVENT("sys_exit_chown", SYS_EXIT_CHOWN);
    ADD_EVENT("sys_enter_lchown", SYS_ENTER_LCHOWN);
    ADD_EVENT("sys_exit_lchown", SYS_EXIT_LCHOWN);
    ADD_EVENT("sys_enter_fchown", SYS_ENTER_FCHOWN);
    ADD_EVENT("sys_exit_fchown", SYS_EXIT_FCHOWN);
    ADD_EVENT("sys_enter_fchownat", SYS_ENTER_FCHOWNAT);
    ADD_EVENT("sys_exit_fchownat", SYS_EXIT_FCHOWNAT);
    ADD_EVENT("sys_enter_utime", SYS_ENTER_UTIME);
    ADD_EVENT("sys_exit_utime", SYS_EXIT_UTIME);
    ADD_EVENT("sys_enter_utimes", SYS_ENTER_UTIMES);
    ADD_EVENT("sys_exit_utimes", SYS_EXIT_UTIMES);
    ADD_EVENT("sys_enter_futimesat", SYS_ENTER_FUTIMESAT);
    ADD_EVENT("sys_exit_futimesat", SYS_EXIT_FUTIMESAT);
    ADD_EVENT("sys_enter_utimensat", SYS_ENTER_UTIMENSAT);
    ADD_EVENT("sys_exit_utimensat", SYS_EXIT_UTIMENSAT);
    ADD_EVENT("sys_enter_access", SYS_ENTER_ACCESS);
    ADD_EVENT("sys_exit_access", SYS_EXIT_ACCESS);
    ADD_EVENT("sys_enter_faccessat", SYS_ENTER_FACCESSAT);
    ADD_EVENT("sys_exit_faccessat", SYS_EXIT_FACCESSAT);
    ADD_EVENT("sys_enter_setxattr", SYS_ENTER_SETXATTR);
    ADD_EVENT("sys_exit_setxattr", SYS_EXIT_SETXATTR);
    ADD_EVENT("sys_enter_lsetxattr", SYS_ENTER_LSETXATTR);
    ADD_EVENT("sys_exit_lsetxattr", SYS_EXIT_LSETXATTR);
    ADD_EVENT("sys_enter_fsetxattr", SYS_ENTER_FSETXATTR);
    ADD_EVENT("sys_exit_fsetxattr", SYS_EXIT_FSETXATTR);
    ADD_EVENT("sys_enter_getxattr", SYS_ENTER_GETXATTR);
    ADD_EVENT("sys_exit_getxattr", SYS_EXIT_GETXATTR);
    ADD_EVENT("sys_enter_lgetxattr", SYS_ENTER_LGETXATTR);
    ADD_EVENT("sys_exit_lgetxattr", SYS_EXIT_LGETXATTR);
    ADD_EVENT("sys_enter_fgetxattr", SYS_ENTER_FGETXATTR);
    ADD_EVENT("sys_exit_fgetxattr", SYS_EXIT_FGETXATTR);
    ADD_EVENT("sys_enter_listxattr", SYS_ENTER_LISTXATTR);
    ADD_EVENT("sys_exit_listxattr", SYS_EXIT_LISTXATTR);
    ADD_EVENT("sys_enter_llistxattr", SYS_ENTER_LLISTXATTR);
    ADD_EVENT("sys_exit_llistxattr", SYS_EXIT_LLISTXATTR);
    ADD_EVENT("sys_enter_flistxattr", SYS_ENTER_FLISTXATTR);
    ADD_EVENT("sys_exit_flistxattr", SYS_EXIT_FLISTXATTR);
    ADD_EVENT("sys_enter_removexattr", SYS_ENTER_REMOVEXATTR);
    ADD_EVENT("sys_exit_removexattr", SYS_EXIT_REMOVEXATTR);
    ADD_EVENT("sys_enter_lremovexattr", SYS_ENTER_LREMOVEXATTR);
    ADD_EVENT("sys_exit_lremovexattr", SYS_EXIT_LREMOVEXATTR);
    ADD_EVENT("sys_enter_fremovexattr", SYS_ENTER_FREMOVEXATTR);
    ADD_EVENT("sys_exit_fremovexattr", SYS_EXIT_FREMOVEXATTR);
    ADD_EVENT("sys_enter_fcntl", SYS_ENTER_FCNTL);
    ADD_EVENT("sys_exit_fcntl", SYS_EXIT_FCNTL);
    ADD_EVENT("sys_enter_dup", SYS_ENTER_DUP);
    ADD_EVENT("sys_exit_dup", SYS_EXIT_DUP);
    ADD_EVENT("sys_enter_dup2", SYS_ENTER_DUP2);
    ADD_EVENT("sys_exit_dup2", SYS_EXIT_DUP2);
    ADD_EVENT("sys_enter_dup3", SYS_ENTER_DUP3);
    ADD_EVENT("sys_exit_dup3", SYS_EXIT_DUP3);
    ADD_EVENT("sys_enter_flock", SYS_ENTER_FLOCK);
    ADD_EVENT("sys_exit_flock", SYS_EXIT_FLOCK);
    ADD_EVENT("sys_enter_read", SYS_ENTER_READ);
    ADD_EVENT("sys_exit_read", SYS_EXIT_READ);
    ADD_EVENT("sys_enter_pread64", SYS_ENTER_PREAD64);
    ADD_EVENT("sys_exit_pread64", SYS_EXIT_PREAD64);
    ADD_EVENT("sys_enter_readv", SYS_ENTER_READV);
    ADD_EVENT("sys_exit_readv", SYS_EXIT_READV);
    ADD_EVENT("sys_enter_preadv", SYS_ENTER_PREADV);
    ADD_EVENT("sys_exit_preadv", SYS_EXIT_PREADV);
    ADD_EVENT("sys_enter_preadv2", SYS_ENTER_PREADV2);
    ADD_EVENT("sys_exit_preadv2", SYS_EXIT_PREADV2);
    ADD_EVENT("sys_enter_write", SYS_ENTER_WRITE);
    ADD_EVENT("sys_exit_write", SYS_EXIT_WRITE);
    ADD_EVENT("sys_enter_pwrite64", SYS_ENTER_PWRITE64);
    ADD_EVENT("sys_exit_pwrite64", SYS_EXIT_PWRITE64);
    ADD_EVENT("sys_enter_writev", SYS_ENTER_WRITEV);
    ADD_EVENT("sys_exit_writev", SYS_EXIT_WRITEV);
    ADD_EVENT("sys_enter_pwritev", SYS_ENTER_PWRITEV);
    ADD_EVENT("sys_exit_pwritev", SYS_EXIT_PWRITEV);
    ADD_EVENT("sys_enter_pwritev2", SYS_ENTER_PWRITEV2);
    ADD_EVENT("sys_exit_pwritev2", SYS_EXIT_PWRITEV2);
    ADD_EVENT("sys_enter_lseek", SYS_ENTER_LSEEK);
    ADD_EVENT("sys_exit_lseek", SYS_EXIT_LSEEK);
    ADD_EVENT("sys_enter_sendfile64", SYS_ENTER_SENDFILE64);
    ADD_EVENT("sys_exit_sendfile64", SYS_EXIT_SENDFILE64);
    ADD_EVENT("sys_enter_inotify_init", SYS_ENTER_INOTIFY_INIT);
    ADD_EVENT("sys_exit_inotify_init", SYS_EXIT_INOTIFY_INIT);
    ADD_EVENT("sys_enter_inotify_init1", SYS_ENTER_INOTIFY_INIT1);
    ADD_EVENT("sys_exit_inotify_init1", SYS_EXIT_INOTIFY_INIT1);
    ADD_EVENT("sys_enter_inotify_add_watch", SYS_ENTER_INOTIFY_ADD_WATCH);
    ADD_EVENT("sys_exit_inotify_add_watch", SYS_EXIT_INOTIFY_ADD_WATCH);
    ADD_EVENT("sys_enter_inotify_rm_watch", SYS_ENTER_INOTIFY_RM_WATCH);
    ADD_EVENT("sys_exit_inotify_rm_watch", SYS_EXIT_INOTIFY_RM_WATCH);
    ADD_EVENT("sys_enter_fanotify_init", SYS_ENTER_FANOTIFY_INIT);
    ADD_EVENT("sys_exit_fanotify_init", SYS_EXIT_FANOTIFY_INIT);
    ADD_EVENT("sys_enter_fanotify_mark", SYS_ENTER_FANOTIFY_MARK);
    ADD_EVENT("sys_exit_fanotify_mark", SYS_EXIT_FANOTIFY_MARK);
    ADD_EVENT("sys_enter_mount", SYS_ENTER_MOUNT);
    ADD_EVENT("sys_exit_mount", SYS_EXIT_MOUNT);
    ADD_EVENT("sys_enter_umount", SYS_ENTER_UMOUNT);
    ADD_EVENT("sys_exit_umount", SYS_EXIT_UMOUNT);
    ADD_EVENT("sys_enter_move_mount", SYS_ENTER_MOVE_MOUNT);
    ADD_EVENT("sys_exit_move_mount", SYS_EXIT_MOVE_MOUNT);
    // 다른 이벤트들도 여기에 추가
    // 메모리 관련 이벤트(프로세스에 추가 예정)
    ADD_EVENT("sys_enter_mmap", SYS_ENTER_MMAP);
    ADD_EVENT("sys_exit_mmap", SYS_EXIT_MMAP);
    ADD_EVENT("sys_enter_munmap", SYS_ENTER_MUNMAP);
    ADD_EVENT("sys_exit_munmap", SYS_EXIT_MUNMAP);
    ADD_EVENT("sys_enter_mprotect", SYS_ENTER_MPROTECT);
    ADD_EVENT("sys_exit_mprotect", SYS_EXIT_MPROTECT);
    ADD_EVENT("sys_enter_pkey_mprotect", SYS_ENTER_PKEY_MPROTECT);
    ADD_EVENT("sys_exit_pkey_mprotect", SYS_EXIT_PKEY_MPROTECT);
    #undef ADD_EVENT
}

__u32 get_event_id(const char* event_str) {
    __u32 index = hash(event_str);
    int attempts = 0;

    while (event_table[index].name != NULL) {
        if (strcmp(event_table[index].name, event_str) == 0) {
            return event_table[index].id;
        }
        index = (index + 1) % MAX_EVENTS;
        if (++attempts >= MAX_EVENTS)  {
            break;
        }
    }
    
    return -1;  // 알 수 없는 이벤트
}