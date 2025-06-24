#include <stdint.h>

typedef struct {
    uint32_t ip;
    int port;
} Socket;

typedef struct {
    char *name;
    Socket *blacklist;
    uint64_t blacklist_count;
    Socket *allowlist;
    uint64_t allowlist_count;
} Interface;


int parse_yaml(const char *filename, Interface **interfaces, int *interface_count);
