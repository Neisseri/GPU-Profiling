// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include "deepflow.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

void sig_int(int signo)
{
    stop = 1;
}

typedef struct
{
    void **address;
    size_t size;
    __u64 call_time;
    __u64 rip;
} malloc_data_t;

int main(int argc, char *argv[])
{
    struct deepflow_bpf *skel;
    int err = 0;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open load and verify BPF application */
    skel = deepflow_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint handler */
    err = deepflow_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    // GPU Memory Info
    struct bpf_map* gpu_mem_map_fd = skel->maps.gpu_memory_info;
    if (!gpu_mem_map_fd) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }
    __u32 key = 0;
    __u32 next_key = 0;
    __u32 value;

    while (!stop)
    {
        key = 0;
        while (bpf_map__get_next_key(gpu_mem_map_fd, &key, &next_key, sizeof(next_key)) == 0) {
            if (bpf_map__lookup_elem(gpu_mem_map_fd, &next_key, sizeof(next_key), &value, sizeof(value), 0) == 0) {
                printf("PID: %u, GPU Memory Usage: %u\n", next_key, value);
            } else {
                fprintf(stderr, "Failed to lookup element for key: %u\n", next_key);
            }
            key = next_key;
        }

        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    deepflow_bpf__destroy(skel);
    return -err;
}
