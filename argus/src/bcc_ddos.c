#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include <linux/ip.h>
#include <linux/if_ether.h>
#define MAX_COUNT 5000
#define BAN_TIME 20000000000

struct packet_info {
    u64 count;
    u64 last_ping;
    u64 ban_time;
};

BPF_TABLE_PINNED("hash", u32, struct packet_info, ip_count_map, 1024, "/sys/fs/bpf/ip_count_map");

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
    u32 ip_32 = ip->saddr;
    struct packet_info *value = ip_count_map.lookup(&ip_32);
    u64 curr_time = bpf_ktime_get_ns() ;
    if (value) {
	if (value->ban_time > curr_time) XDP_DROP;
        value->count++;
	value->last_ping = curr_time;
	if (value->count > MAX_COUNT)
	{
		value->ban_time = curr_time + BAN_TIME; 
		return XDP_DROP;		
	}
    } else {
        struct packet_info new_value = {
            .count = 1,
            .last_ping = curr_time,
	    .ban_time = 0 
        };
	ip_count_map.update( &ip_32, &new_value);
    }

    return XDP_PASS;
}

