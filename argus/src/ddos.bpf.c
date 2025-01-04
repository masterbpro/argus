#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdint.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

static inline uint16_t bpf_htons(uint16_t val) {
    return __builtin_bswap16(val);
}

struct packet_info {
    uint64_t count;
    uint64_t last_ping;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint8_t[4]);
    __type(value, struct packet_info);
} ip_count_map SEC(".maps");

SEC("xdp")
int argus_count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    uint8_t ip_key[4] = {
        (ip->saddr >> 24) & 0xFF,
        (ip->saddr >> 16) & 0xFF,
        (ip->saddr >> 8) & 0xFF,
        ip->saddr & 0xFF
    };
    struct packet_info *value = bpf_map_lookup_elem(&ip_count_map, ip_key);
    if (value) {
        value->count++;
        value->last_ping = bpf_ktime_get_ns() / 1000000000;
    } else {
        struct packet_info new_value = {};
        new_value.count = 1;
        new_value.last_ping = bpf_ktime_get_ns() / 1000000000;
        bpf_map_update_elem(&ip_count_map, ip_key, &new_value, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";