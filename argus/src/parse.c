#include <yaml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "parse.h"
	
int parse_yaml(const char *filename, Interface **interfaces, int *interface_count) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return 1;
    }

    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(file);
        return 1;
    }

    yaml_parser_set_input_file(&parser, file);

    int done = 0;
    yaml_event_t event;
    Interface *tmp_interfaces = NULL;
    int count = 0;
    int current_interface = -1;
    int in_blacklist = 0;
    int in_allowlist = 0;
    int in_sequence = 0;
    int in_mapping = 0;
    int current_socket_type = 0;
    char *current_key = NULL;
    Socket *current_socket = NULL;

    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Parser error %d\n", parser.error);
            break;
        }

        switch (event.type) {
            case YAML_SEQUENCE_START_EVENT:
                in_sequence = 1;
                break;
                
            case YAML_SEQUENCE_END_EVENT:
                in_sequence = 0;
                in_blacklist = 0;
                in_allowlist = 0;
                break;
                
            case YAML_MAPPING_START_EVENT:
                in_mapping = 1;
                if (in_sequence && current_interface >= 0) {
                    if (in_blacklist) {
                        tmp_interfaces[current_interface].blacklist_count++;
                        tmp_interfaces[current_interface].blacklist = realloc(
                            tmp_interfaces[current_interface].blacklist,
                            tmp_interfaces[current_interface].blacklist_count * sizeof(Socket)
                        );
                        current_socket = &tmp_interfaces[current_interface].blacklist[
                            tmp_interfaces[current_interface].blacklist_count - 1];
                        memset(current_socket, 0, sizeof(Socket));
                    } else if (in_allowlist) {
                        tmp_interfaces[current_interface].allowlist_count++;
                        tmp_interfaces[current_interface].allowlist = realloc(
                            tmp_interfaces[current_interface].allowlist,
                            tmp_interfaces[current_interface].allowlist_count * sizeof(Socket)
                        );
                        current_socket = &tmp_interfaces[current_interface].allowlist[
                            tmp_interfaces[current_interface].allowlist_count - 1];
                        memset(current_socket, 0, sizeof(Socket));
                    }
                }
                break;
                
            case YAML_MAPPING_END_EVENT:
                in_mapping = 0;
                current_key = NULL;
                current_socket = NULL;
                break;
                
            case YAML_SCALAR_EVENT: {
                char *value = (char *)event.data.scalar.value;
                
                if (strcmp(value, "name") == 0) {
                    current_key = strdup("name");
                }
                else if (strcmp(value, "blacklist") == 0) {
                    in_blacklist = 1;
                    current_socket_type = 1;
                }
                else if (strcmp(value, "allowlist") == 0) {
                    in_allowlist = 1;
                    current_socket_type = 2;
                }
                else if (strcmp(value, "ip") == 0) {
                    if (current_socket) {
                        current_key = strdup("ip");
                    }
                }
                else if (strcmp(value, "port") == 0) {
                    if (current_socket) {
                        current_key = strdup("port");
                    }
                }
                else {
                    if (current_key) {
                        if (strcmp(current_key, "name") == 0) {
                            count++;
                            tmp_interfaces = realloc(tmp_interfaces, count * sizeof(Interface));
                            memset(&tmp_interfaces[count - 1], 0, sizeof(Interface));
                            tmp_interfaces[count - 1].name = strdup(value);
                            current_interface = count - 1;
                        } 
                        else if (current_socket && strcmp(current_key, "ip") == 0) {
                            current_socket->ip = (uint32_t)atoi(value);
                        }
                        else if (current_socket && strcmp(current_key, "port") == 0) {
                            current_socket->port = atoi(value);
                        }
                        free(current_key);
                        current_key = NULL;
                    }
                }
                break;
            }
                
            case YAML_STREAM_END_EVENT:
                done = 1;
                break;
                
            default:
                break;
        }
        
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);

    *interfaces = tmp_interfaces;
    *interface_count = count;
    return 0;
}

