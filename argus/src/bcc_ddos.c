#include <linux/if_ether.h>
#include <linux/ip.h>

#define THRESHOLD 200
#define TIME_WINDOW_NS 1000000000

struct rate_limit_entry {
    u64 last_update;
    u32 packet_count;
};

BPF_TABLE_PINNED("hash" , u32, struct rate_limit_entry, rate_limit_map, 1024, "/sys/fs/bpf/rate_limit_map");

int argus_count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;


    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = iph->saddr;

    struct rate_limit_entry *entry = rate_limit_map.lookup(&src_ip);
    u64 current_time = bpf_ktime_get_ns();

    if (entry) {
        if (current_time - entry->last_update < TIME_WINDOW_NS) {
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD) {
                return XDP_DROP;
            }
        } else {
            entry->last_update = current_time;
            entry->packet_count = 1;
        }
    } else {
        struct rate_limit_entry new_entry = {
            .last_update = current_time,
            .packet_count = 1
        };
        rate_limit_map.update(&src_ip, &new_entry);
    }

    return XDP_PASS;
}
