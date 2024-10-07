#ifndef EBPF_EXTRACTOR_H
#define EBPF_EXTRACTOR_H

#include "libbpf.h"

#define MAP_FILETYPE ".maps"
#define INSN_FILETYPE ".insns"
#define INSN_READABLE_FILETYPE ".txt"
#define RELOC_FILETYPE ".rel"

int ebpf_extractor__init();

void ebpf_extractor__deinit();

int ebpf_extractor__extract(const char *path);

int ebpf_extractor__extract_maps(struct bpf_object *obj);

void ebpf_extractor__fix_progname(const char *prog_name, const size_t prog_len, char *fixed_progname);

int ebpf_extractor__extract_insns(struct bpf_program *prog);

int ebpf_extractor__extract_relocs(struct bpf_program *prog);

#endif