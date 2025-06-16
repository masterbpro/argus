struct packet_info {
    u64 count;
    u64 ban_time;
};

BPF_TABLE_PINNED("hash", u32, struct packet_info, ip_count_map, 1024, "/sys/fs/bpf/ip_count_map");


int foo(void* ctx)
{
	return 0;
}

