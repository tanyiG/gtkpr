//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    // Drop all incoming packages
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";