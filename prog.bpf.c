#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

typedef unsigned int u32;

struct fault_data_t {
    unsigned long faulted_address;
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB ring buffer
} ringbuf SEC(".maps");

SEC("fentry/handle_mm_fault")
int BPF_PROG(handle_mm_fault, struct vm_area_struct *vma, unsigned long address,
             unsigned int flags, struct pt_regs *regs) {
    struct fault_data_t *data;

    // Reserve space in the ring buffer
    data = bpf_ringbuf_reserve(&ringbuf, sizeof(struct fault_data_t), 0);
    if (!data) {
        return 0;  // Not enough space in the ring buffer
    }

    // Store the faulted address and PID
    data->faulted_address = address;
    data->pid = bpf_get_current_pid_tgid() >> 32;

    // Submit the data to the ring buffer
    bpf_ringbuf_submit(data, 0);
    return 0;
}