#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PROG_PATH "/mnt/e/Program/ebpf-cuda-examples/cuda/cpmem"

// GPU Memory Info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // tgid
    __type(value, __u32); // used GPU memory
} gpu_memory_info SEC(".maps");

// (__u64)(void* devPtr) -> malloc size
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); // malloc address
    __type(value, __u32); // malloc size
} cuda_malloc_hash SEC(".maps");

typedef struct {
    __u64 ptr;
    __u64 size; // DEBUG: use __u64 instead of __u32 to ensure struct alignment
} malloc_info_t;

// PID -> (void** devPtr)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // PID
    __type(value, malloc_info_t);
} malloc_ptr_info SEC(".maps");

SEC("uprobe/" PROG_PATH ":cudaMalloc")
int BPF_UPROBE(cuda_malloc, void **devPtr, size_t size)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);

    __u32* mem_data = (__u32*)bpf_map_lookup_elem(&gpu_memory_info, &tgid);
    if (mem_data) {
        *mem_data += size;
    } else {
        __u32 new_mem_data = size;
        bpf_map_update_elem(&gpu_memory_info, &tgid, &new_mem_data, BPF_ANY);
    }

    malloc_info_t* ptr_data = (__u64*)bpf_map_lookup_elem(&malloc_ptr_info, &tgid);
    if (ptr_data) {
        ptr_data->ptr = (__u64)(devPtr);
        ptr_data->size = size;
    } else {
        malloc_info_t new_ptr_data = {
            .ptr = (__u64)(devPtr),
            .size = size,
        };
        bpf_map_update_elem(&malloc_ptr_info, &tgid, &new_ptr_data, BPF_ANY);
    }

    __u32 m_data = 0;
    if (mem_data)
        m_data = *mem_data;
    const char fmt[] = "cudaMalloc called: pid = %u, mem_data = %u, (__u64)devPtr = %llu\n";
    bpf_trace_printk(fmt, sizeof(fmt), tgid, m_data, (__u64)devPtr);

    return 0;
}

SEC("uretprobe/" PROG_PATH ":cudaMalloc")
int BPF_URETPROBE(cuda_malloc_ret, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __u32 pid = (__u32)id;

    if (ret != 0) // Malloc failed
    {
        return 0;
    }

    malloc_info_t* malloc_info_data = (__u64*)bpf_map_lookup_elem(&malloc_ptr_info, &tgid);
    void* devPtr = NULL;
    __u32 malloc_size = 0;
    if (malloc_info_data) {
        devPtr = (void*)(malloc_info_data->ptr);
        malloc_size = malloc_info_data->size;

        void* devPtr_;
        bpf_probe_read_user(&devPtr_, sizeof(void*), devPtr);
        __u64 addr = (__u64)(devPtr_);

        const char fmt[] = "cudaMalloc Ret: pid = %u, (__u64)devPtr = %llu, addr = %llu\n";
        bpf_trace_printk(fmt, sizeof(fmt), tgid, malloc_info_data->ptr, addr);

        __u32* data_size = (__u32*)bpf_map_lookup_elem(&cuda_malloc_hash, &addr);
        if (data_size) {
            *data_size = malloc_size;
        } else {
            bpf_map_update_elem(&cuda_malloc_hash, &addr, &malloc_size, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/" PROG_PATH ":cudaFree")
int BPF_UPROBE(cuda_free, void *devPtr)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);

    // cuda malloc hash
    __u64 addr = (__u64)(devPtr);

    const char fmt[] = "cudaFree called: pid = %u, (__u64)devPtr = %llu\n";
    bpf_trace_printk(fmt, sizeof(fmt), tgid, addr);

    __u32* malloc_size = (__u32*)bpf_map_lookup_elem(&cuda_malloc_hash, &addr);
    __u32 m_size = 0;
    if (malloc_size) {
        m_size = *malloc_size;
    }

    __u32* mem_data = (__u32*)bpf_map_lookup_elem(&gpu_memory_info, &tgid);
    if (mem_data) {
        *mem_data -= m_size;
    }

    return 0;
}
