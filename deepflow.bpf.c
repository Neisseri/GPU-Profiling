#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PROG_PATH "/mnt/e/Program/ebpf-cuda-examples/cuda/cpmem"

static void *local_memset(void *ptr, int value, size_t num)
{
    char *p = ptr;
    while (num--)
    {
        *p = (char)value;
    }
    return ptr;
}

typedef struct
{
    void **address;
    size_t size;
    __u64 call_time;
    __u64 rip;
} malloc_data_t;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, malloc_data_t);
} cuda_malloc_info SEC(".maps");

static malloc_data_t *cuda_malloc_info_lookup(__u32 *tgid)
{
    return (malloc_data_t *)bpf_map_lookup_elem(&cuda_malloc_info, tgid);
}

static long cuda_malloc_info_update(__u32 *tgid, malloc_data_t *data)
{
    return bpf_map_update_elem(&cuda_malloc_info, tgid, data, BPF_ANY);
}

static long cuda_malloc_info_delete(__u32 *tgid)
{
    return bpf_map_delete_elem(&cuda_malloc_info, tgid);
}

SEC("uprobe/" PROG_PATH ":cudaMalloc")
int BPF_UPROBE(cuda_malloc, void **devPtr, size_t size)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);

    // print cudaMalloc
    const char fmt[] = "cudaMalloc called: pid = %u, size = %zu\n";
    bpf_trace_printk(fmt, sizeof(fmt), tgid, size);

    malloc_data_t *data = cuda_malloc_info_lookup(&tgid);
    __u64 call_time = bpf_ktime_get_ns();

    if (data != NULL)
    {
        data->address = devPtr;
        data->size = size;
        data->call_time = call_time;
        data->rip = PT_REGS_IP(ctx);
    }
    else
    {
        malloc_data_t newdata = {
            .address = devPtr,
            .size = size,
            .call_time = call_time,
            .rip = PT_REGS_IP(ctx),
        };
        cuda_malloc_info_update(&tgid, &newdata);
    }

    return 0;
}

#define MAX_CMDLINE_LEN 1024
struct stack_trace_key_t
{
    __u32 tgid;
    __u32 pid;
    __u32 cpu;
    char comm[MAX_CMDLINE_LEN];
    __u64 timestamp;
    __u64 mem_addr;
    __u64 mem_size;
};

struct stack_trace_t
{
    // TODO
};

static void add_frame(struct stack_trace_t *state, __u64 ip)
{
    // TODO
}

typedef struct
{
    struct stack_trace_key_t key;
    struct stack_trace_t stack;
    struct
    {
        __u64 ip;
        __u64 sp;
        __u64 bp;
    } regs;
} unwind_stack_t;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, unwind_stack_t);
} heap SEC(".maps");

static unwind_stack_t *heap_lookup(__u32 *key)
{
    return (unwind_stack_t *)bpf_map_lookup_elem(&heap, key);
}

SEC("uretprobe/" PROG_PATH ":cudaMalloc")
int BPF_URETPROBE(cuda_malloc_ret, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(id >> 32);
    __u32 pid = (__u32)id;

    // print cudaMalloc ret
    const char fmt[] = "cudaMalloc Ret: pid = %u\n";
    bpf_trace_printk(fmt, sizeof(fmt), tgid);

    if (ret != 0) // Malloc failed
    {
        return 0;
    }

    malloc_data_t *data_in_map = cuda_malloc_info_lookup(&tgid);
    if (data_in_map != NULL)
    {
        return 0;
    }
    malloc_data_t data;
    bpf_probe_read(&data, sizeof(data), data_in_map);
    cuda_malloc_info_delete(&tgid); // QUESTION: Why delete here?

    __u32 zero = 0;
    unwind_stack_t *state = heap_lookup(&zero); // QUESTION: Where to get the default value?
    if (state == NULL)
    {
        const char fmt[] = "ERROR: state is NULL\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return 0;
    }
    local_memset(state, 0, sizeof(unwind_stack_t));

    struct stack_trace_key_t *key = &state->key;
    key->tgid = tgid;
    key->pid = pid;

    if (tgid == pid && pid == 0)
    {
        return 0; // Ignore kernel threads
    }

    key->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&key->comm, sizeof(key->comm));
    key->timestamp = bpf_ktime_get_ns();

    bpf_probe_read_user((void *)&key->mem_addr, sizeof(key->mem_addr), (void *)data.address);
    key->mem_size = data.size;

    // Add one frame for cudaMalloc
    // Native unwinding start from uretprobe, which has the ret state after cudaMalloc return
    add_frame(&state->stack, data.rip);

    state->regs.ip = PT_REGS_IP(ctx);
    state->regs.sp = PT_REGS_SP(ctx);
    state->regs.bp = PT_REGS_FP(ctx);
    add_frame(&state->stack, state->regs.ip);
    // bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_DWARF_UNWIND_IDX); // QUESTION & TODO: What is this?

    return 0;
}

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} cuda_memory_output SEC(".maps");

SEC("uprobe/" PROG_PATH ":cudaFree")
int BPF_UPROBE(cuda_free, void *devPtr)
{
    __u64 id = bpf_get_current_pid_tgid();

    // print cudaFree
    __u32 tgid = (__u32)(id >> 32);
    const char fmt[] = "cudaFree called: pid = %u, devPtr = %p\n";
    bpf_trace_printk(fmt, sizeof(fmt), tgid, devPtr);

    __u32 zero = 0;
    unwind_stack_t *state = heap_lookup(&zero);
    if (state == NULL)
    {
        const char fmt[] = "ERROR: state is NULL\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return 0;
    }
    local_memset(state, 0, sizeof(unwind_stack_t)); // QUIESTION: state is cleared without use?

    struct stack_trace_key_t *key = &state->key;
    key->tgid = (__u32)(id >> 32);
    key->pid = (__u32)id;

    if (key->tgid == key->pid && key->pid == 0)
    {
        return 0; // Ignore kernel threads
    }

    key->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&key->comm, sizeof(key->comm));
    key->timestamp = bpf_ktime_get_ns();

    key->mem_addr = (__u64)devPtr;

    bpf_perf_event_output(ctx, &cuda_memory_output, BPF_F_CURRENT_CPU, &state->key, sizeof(state->key));

    return 0;
}
