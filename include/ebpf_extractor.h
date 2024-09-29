#ifndef EBPF_EXTRACTOR_H
#define EBPF_EXTRACTOR_H

#include "libbpf.h"

int ebpf_extractor__init();

void ebpf_extractor__deinit();

int ebpf_extractor__extract(const char *path);

int ebpf_extractor__extract_maps(struct bpf_object *obj);

#endif