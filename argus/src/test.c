#include <stdio.h>
#include "parse.h"



int main(int argc, char* argv[])
{
	Interface *interfaces = NULL;
	int interface_count = 0;
	parse_yaml("1.yaml", &interfaces, &interface_count);
	for (int i = 0; i < interface_count; i++)
	{
		printf("%s\n", interfaces[i].name);
		printf("\nblacklist:\n");
		for (int j = 0; j < interfaces[i].blacklist_count; j++)
		{
			printf("%s : %d\n", interfaces[i].blacklist[j].ip, interfaces[i].blacklist[j].port);
		}
		printf("\nallowlist:\n");
		for (int j = 0; j < interfaces[i].allowlist_count; j++)
                {
                        printf("%s : %d\n", interfaces[i].allowlist[j].ip, interfaces[i].allowlist[j].port);
                }
	}

	return 0;
}
