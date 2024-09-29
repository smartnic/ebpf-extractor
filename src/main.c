#include <stdio.h>
#include <stdlib.h>

#include "ebpf_extractor.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "USAGE: %s </path/to/object.o>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (ebpf_extractor__init() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    int val = ebpf_extractor__extract(argv[1]);

    ebpf_extractor__deinit();
    return val;
}