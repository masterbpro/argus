#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_link *link;
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

    system("mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true");
    bpf_link__pin(link, "/sys/fs/bpf/ddos_link");

    bpf_object__close(obj);
    return 0;
}
