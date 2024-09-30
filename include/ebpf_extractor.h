#ifndef EBPF_EXTRACTOR_H
#define EBPF_EXTRACTOR_H

#include "libbpf.h"

#define MAP_FILETYPE ".maps"

int ebpf_extractor__init();

void ebpf_extractor__deinit();

int ebpf_extractor__extract(const char *path);

int ebpf_extractor__extract_maps(struct bpf_object *obj);

void ebpf_extractor__fix_progname(const char *prog_name, const size_t prog_len, char *fixed_progname);

#endif