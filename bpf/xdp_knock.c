//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define KNOCK_TIMEOUT_NS  30000000000ULL
#define ACCESS_DURATION_NS 300000000000ULL
#define MAX_KNOCK_STEPS 8

struct debug_event {
    __u32 src_ip;
    __u16 src_port;
    __u8  event_type; // 0: NEW_KNOCK, 1: WRONG_KNOCK, 2: STEP_OK, 3: SEQUENCE_OK, 4: TCP_ACCESS
    __u8  step;
    __u16 expected_port;
    __u64 timestamp;
};

struct knock_state {
    __u32 step;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct knock_state);
} knock_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_KNOCK_STEPS);
    __type(key, __u32);
    __type(value, __u16);
} knock_sequence_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5000);
    __type(key, __u32);
    __type(value, __u64);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} debug_events SEC(".maps");

SEC("xdp")
int xdp_knock(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // --- TCP traffic to protected port (22) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_DROP;

        if (tcp->dest == bpf_htons(22)) {
            __u64 *expiry = bpf_map_lookup_elem(&allowed_ips, &src_ip);
            if (expiry && now < *expiry) {
                struct debug_event evt = {
                    .src_ip = src_ip,
                    .event_type = 4,
                    .timestamp = now
                };
                bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                return XDP_PASS;
            }
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    // --- UDP knock packets ---
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_DROP;

    __u16 dport = udp->dest;

    struct knock_state *state = bpf_map_lookup_elem(&knock_state_map, &src_ip);
    struct knock_state new_state = {0};
    if (!state) {
        new_state.step = 0;
        new_state.last_seen_ns = now;
        state = &new_state;
    } else if (now - state->last_seen_ns > KNOCK_TIMEOUT_NS) {
        state->step = 0;
    }

    __u32 step_key = state->step;
    __u16 *expected_port = bpf_map_lookup_elem(&knock_sequence_map, &step_key);
    if (!expected_port || *expected_port == 0) {
        state->step = 0;
        state->last_seen_ns = now;
        bpf_map_update_elem(&knock_state_map, &src_ip, state, BPF_ANY);
        return XDP_DROP;
    }

    struct debug_event evt = {
        .src_ip = src_ip,
        .src_port = bpf_ntohs(dport),
        .step = step_key,
        .expected_port = *expected_port,
        .timestamp = now
    };

    if (bpf_ntohs(dport) == *expected_port) {
        state->step++;
        state->last_seen_ns = now;

        __u32 next_key = state->step;
        __u16 *next_port = bpf_map_lookup_elem(&knock_sequence_map, &next_key);
        if (!next_port || *next_port == 0) {
            __u64 expiry = now + ACCESS_DURATION_NS;
            bpf_map_update_elem(&allowed_ips, &src_ip, &expiry, BPF_ANY);
            bpf_map_delete_elem(&knock_state_map, &src_ip);
            evt.event_type = 3; // SEQUENCE_OK
        } else {
            bpf_map_update_elem(&knock_state_map, &src_ip, state, BPF_ANY);
            evt.event_type = 2; // STEP_OK
        }
    } else {
        state->step = 0;
        state->last_seen_ns = now;
        bpf_map_update_elem(&knock_state_map, &src_ip, state, BPF_ANY);
        evt.event_type = 1; // WRONG_KNOCK
    }

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";