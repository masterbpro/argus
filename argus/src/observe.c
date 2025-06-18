struct rate_limit_entry {
    u64 last_update;
    u32 packet_count;
};

BPF_TABLE_PINNED("hash", u32, u64, ban_map, 1024, "/sys/fs/bpf/ban_map");
BPF_TABLE_PINNED("hash" , u32, struct rate_limit_entry, rate_limit_map, 1024, "/sys/fs/bpf/rate_limit_map");


int foo(void* ctx)
{
	return 0;
}

