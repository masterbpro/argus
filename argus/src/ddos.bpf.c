#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdint.h>

#define RATE 1000
#define BURST 2000
#define NSEC_PER_SEC 1000000000ULL

struct token_bucket {
    uint64_t tokens;
    uint64_t last_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, struct token_bucket);
} buckets SEC(".maps");

SEC("xdp")
int argus_ddos(struct xdp_md *ctx) {
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint64_t now = bpf_ktime_get_ns();

    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    uint32_t src = ip->saddr;
    struct token_bucket *tb = bpf_map_lookup_elem(&buckets, &src);
    if (!tb) {
        struct token_bucket init = { .tokens = BURST, .last_ts = now };
        bpf_map_update_elem(&buckets, &src, &init, BPF_ANY);
        tb = bpf_map_lookup_elem(&buckets, &src);
        if (!tb) return XDP_PASS;
    }

    uint64_t delta = now - tb->last_ts;
    uint64_t add = delta * RATE / NSEC_PER_SEC;
    if (add) {
        tb->tokens += add;
        if (tb->tokens > BURST) tb->tokens = BURST;
        tb->last_ts = now;
    }

    if (tb->tokens == 0)
        return XDP_DROP;
    tb->tokens--;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
