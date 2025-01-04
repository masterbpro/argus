#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <BPF_PROGRAM_FILE> <INTERFACE_NAME>\n", argv[0]);
        return 1;
    }

    const char *program_file = argv[1];
    const char *interface_name = argv[2];

    struct bpf_object *obj;
    int prog_fd;

    obj = bpf_object__open_file(program_file, NULL);
    if (!obj) {
        perror("Error opening BPF object");
        return 1;
    }
    if (bpf_object__load(obj)) {
        perror("Error loading BPF object");
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "xdp"));
    if (prog_fd < 0) {
        perror("Error getting program file descriptor");
        bpf_object__close(obj);
        return 1;
    }
    int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        perror("Error getting interface index");
        bpf_object__close(obj);
        return 1;
    }
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("Error attaching program to interface");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program successfully loaded and attached to %s\n", interface_name);
    bpf_object__close(obj);
    return 0;
}
