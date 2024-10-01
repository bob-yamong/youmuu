// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/syscall.h>   // Added for __NR_* constants
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"

#define MAX_SYSCALL_ENTRIES 256

static volatile bool exiting = false;

void handle_signal(int sig)
{
    exiting = true;
}

// Initialize syscall map
void init_syscall_map(struct process_monitor_bpf *skel)
{
    // Monitoring system calls
    struct {
        int nr;
        const char *name;
    } syscall_list[] = {
        { __NR_fork, "fork" },
        { __NR_vfork, "vfork" },
        { __NR_clone, "clone" },
        { __NR_execve, "execve" },
        { __NR_execveat, "execveat" },
        { __NR_exit, "exit" },
        { __NR_exit_group, "exit_group" },
        { __NR_kill, "kill" },
        { __NR_tgkill, "tgkill" },
        { __NR_tkill, "tkill" },
        { __NR_wait4, "wait4" },
        { __NR_waitid, "waitid" },
        { __NR_ptrace, "ptrace" },
        // Add more if needed
    };

    int size = sizeof(syscall_list) / sizeof(syscall_list[0]);
    for (int i = 0; i < size; i++) {
        int nr = syscall_list[i].nr;
        char syscall_name[16];
        snprintf(syscall_name, sizeof(syscall_name), "%s", syscall_list[i].name);
        bpf_map__update_elem(skel->maps.syscall_map, &nr, sizeof(nr), &syscall_name, sizeof(syscall_name), BPF_ANY);
    }
}

// Corrected function signature
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct event *e = data;
    printf("Process syscall: %s (pid=%d, uid=%d, comm=%s)\n",
           e->syscall, e->pid, e->uid, e->comm);
}

int main(int argc, char **argv)
{
    struct process_monitor_bpf *skel;
    int err;

    // Signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Increase RLIMIT_MEMLOCK
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    // Open and load eBPF program
    skel = process_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton\n");
        return 1;
    }

    // Initialize syscall map
    init_syscall_map(skel);

    // Attach eBPF program
    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        goto cleanup;
    }

    // Set up perf buffer
    struct perf_buffer *pb = NULL;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        goto cleanup;
    }

    printf("Process monitoring started. Press Ctrl+C to exit.\n");

    // Event loop
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    perf_buffer__free(pb);
    process_monitor_bpf__destroy(skel);
    return -err;
}
