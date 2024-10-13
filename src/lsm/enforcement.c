#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "enforcement.skel.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define MAP_PIN_PATH "/sys/fs/bpf/policy_map"

#define MAX_STRING_SIZE 256
#define TASK_COMM_LEN 80

static volatile bool exiting = false;

enum section_nr {
	SECID_BPRM_CHECK_SECURITY,
	SECID_FILE_OPEN,
	SECID_SB_MOUNT,
	SECID_SB_REMOUNT,
	SECID_SB_UMOUNT,
	SECID_SOCKET_BIND,
	SECID_SOCKET_CONNECT,
	SECID_TASK_FIX_SETUID,
};

typedef struct bufkey {
  char path[MAX_STRING_SIZE];
  char source[MAX_STRING_SIZE];
} bufs_k;

typedef struct {
  __u64 ts;

  // conatiner identifier
  __u32 pid_id;
  __u32 mnt_id;

  // process identifier
  __u32 host_ppid;
  __u32 host_pid;

  __u32 ppid;
  __u32 pid;
  __u32 uid;

  // control group identifier
  __u64 cgroup_id;

  enum section_nr event_id;
  __s64 retval;

  __u8 comm[TASK_COMM_LEN];

  bufs_k data;
} event;

static int print_event(void *ctx, void *data, size_t data_sz) {
    event *e = (event *)data;
    char timestamp[32];
    time_t event_time = e->ts / 1000000000;  // Convert nanoseconds to seconds
    struct tm *tm_info = localtime(&event_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("--------- Event ---------\n");
    printf("Timestamp: %s.%09llu\n", timestamp, e->ts % 1000000000);
    printf("Container ID: pid_ns=%u, mnt_ns=%u\n", e->pid_id, e->mnt_id);
    printf("Process: host_ppid=%u, host_pid=%u, ppid=%u, pid=%u, uid=%u\n", 
           e->host_ppid, e->host_pid, e->ppid, e->pid, e->uid);
    printf("Cgroup ID: %llu\n", e->cgroup_id);
    printf("Event ID: %d\n", e->event_id);
    printf("Return Value: %lld\n", e->retval);
    printf("Command: %s\n", e->comm);
    printf("Data:\n");
    printf("  Path: %s\n", e->data.path);
    printf("  Source: %s\n", e->data.source);
    printf("--------------------------\n\n");

    return 0;
}

void handle_signal(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    struct enforcement_bpf *skel;
    struct ring_buffer *rb = NULL;

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = enforcement_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    int err, map_fd = bpf_obj_get(MAP_PIN_PATH);

    // check if the map already exists
    if (map_fd < 0) {
        fprintf(stderr, "No existing map found, creating a new one.\n");

        err = bpf_object__pin_maps(skel->obj, BPF_FS_PATH);
        if (err) {
            fprintf(stderr, "Failed to pin maps: %d\n", err);
            goto cleanup;
        }

        map_fd = bpf_obj_get(MAP_PIN_PATH);
        if (map_fd < 0) {
            fprintf(stderr, "Failed to open pinned map: %s\n", strerror(errno));
            goto cleanup;
        }
    } else {
        fprintf(stdout, "Found existing map, reusing it.\n");

        bpf_map__set_pin_path(skel->maps.policy_map, MAP_PIN_PATH);
        err = bpf_map__reuse_fd(skel->maps.policy_map, map_fd);
        if (err) {
            fprintf(stderr, "Failed to reuse existing map: %d\n", err);
            goto cleanup;
        }
    }

    err = enforcement_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = enforcement_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 링 버퍼 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), print_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed Create Ring Buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            goto cleanup;
        } else if (err > 0) {
            printf("Processed %d events\n", err);
        }
    }

cleanup:
    ring_buffer__free(rb);
    enforcement_bpf__destroy(skel);
    return -err;
}