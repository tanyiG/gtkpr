//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Ethernet protocol types
#define ETH_P_IP 0x0800

// IP protocol numbers
#define IPPROTO_UDP 17

// Test port for initial filtering (network byte order)
#define TEST_PORT 12345

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    // Drop all incoming packages
    return XDP_DROP;
}

SEC("xdp")
int xdp_knock(struct xdp_md *ctx) {
    // Pointers to packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP; // Packet too short
    }

    // 2. Check if it's IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not IPv4, let it through for now
    }

    // 3. Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    // 4. Check if it's UDP
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS; // Not UDP, ignore for now
    }

    // 5. Parse UDP header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        return XDP_DROP;
    }

    // 6. Check destination port
    __u16 dport = udp->dest;
    if (dport == bpf_htons(TEST_PORT)) {
        // This is our test knock port - drop for now (will be processed later)
        return XDP_DROP;
    }

    // Pass all other traffic
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";