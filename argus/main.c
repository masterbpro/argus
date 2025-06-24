#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "src/parse.h"

int main(int argc, char **argv) {
   	
	struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_link *link;
    Interface *interfaces = NULL;
	int interfaces_count = 0;
	int ifindex;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <bpf object> <ifname>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", argv[1]);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        printf("Attaching program '%s'\n", bpf_program__name(prog));
        break;
    }
    if (!prog) {
        fprintf(stderr, "No BPF programs found in object\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    struct bpf_map *blacklist = bpf_object__find_map_by_name(obj, "blacklist");
    struct bpf_map *allowlist = bpf_object__find_map_by_name(obj, "allowlist");
    char blacklist_name[256], allowlist_name[256];
    
	system("mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true");
	snprintf(allowlist_name, sizeof(allowlist_name), "/sys/fs/bpf/%s_allowlist", argv[2]);
    snprintf(blacklist_name, sizeof(blacklist_name), "/sys/fs/bpf/%s_blacklist", argv[2]);
    if (!bpf_map__is_pinned(blacklist)) bpf_map__pin(blacklist, blacklist_name);	   	
	if (!bpf_map__is_pinned(allowlist)) bpf_map__pin(allowlist, allowlist_name);
	bpf_link__pin(link, "/sys/fs/bpf/ddos_link");
	
	if (parse_yaml("config.yaml", &interfaces, &interfaces_count))
    {
        fprintf(stderr, "Failed to parse config.yaml/n");
        bpf_object__close(obj);
        return 1;
    }
    struct bpf_map *cur_blacklist = NULL, *cur_allowlist = NULL;

    for (int i = 0; i < interfaces_count ; i++)
    {
        snprintf(blacklist_name, sizeof(blacklist_name), "/sys/fs/bpf/%s_blacklist", interfaces[i].name);
        snprintf(allowlist_name, sizeof(blacklist_name), "/sys/fs/bpf/%s_allowlist", interfaces[i].name);
        cur_blacklist = bpf_obj_get(blacklist_name);
        cur_allowlist = bpf_obj_get(allowlist_name);
        
        if (cur_blacklist < 0) 
            fprintf(stderr, "Error opening %s\n", blacklist_name);
        if (cur_allowlist < 0) 
            fprintf(stderr, "Error opening %s\n", allowlist_name);
        
        if (!cur_blacklist) fprintf(stderr, "Error while opening map %s\0", blacklist_name);
        if (!cur_allowlist) fprintf(stderr, "Error while opening map %s\0", allowlist_name);
        for (int j = 0; j < interfaces[i].blacklist_count; j++)
        {
            interfaces[i].blacklist[j].port = 0;
            bpf_map__update_elem(cur_blacklist, &interfaces[i].blacklist[j], sizeof(Socket), true, sizeof(bool), BPF_ANY);
        }
        for (int j = 0; j < interfaces[i].allowlist_count; j++)
        {
            interfaces[i].allowlist[j].port = 0;
            bpf_map__update_elem(cur_allowlist, &interfaces[i].allowlist[j], sizeof(Socket), true, sizeof(bool), BPF_ANY);
        }
    }
    bpf_object__close(obj);
    return 0;
}
