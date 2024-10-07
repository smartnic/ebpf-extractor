#ifndef LIBBPF_EXTRACTOR_H
#define LIBBPF_EXTRACTOR_H

/* NOTE: must prepend each function definition with LIBBPF_API, otherwise the 
 * -function will not be publicly linked through the shared object.
 */

LIBBPF_API int bpf_object__relocate_data_wrapper(struct bpf_object *obj, struct bpf_program *prog)
{
    return bpf_object__relocate_data(obj, prog);
}

LIBBPF_API int bpf_map__set_fd(struct bpf_map *map, int fd)
{
    if (!map)
		return libbpf_err(-EINVAL);

	/*if (!map_is_created(map))
		return -1;*/

	map->fd = fd;
    return 0;
}

LIBBPF_API int bpf_program__nr_reloc(struct bpf_program *prog)
{
	if (!prog)
		return libbpf_err(-EINVAL);
	
	return prog->nr_reloc;
}

LIBBPF_API int bpf_reloc__type(struct bpf_program *prog, int index)
{
	if (!prog || index < 0 || index >= prog->nr_reloc)
		return libbpf_err(-EINVAL);
	
	return prog->reloc_desc[index].type;	
}

LIBBPF_API int bpf_reloc__insn_idx(struct bpf_program *prog, int index)
{
	if (!prog || index < 0 || index >= prog->nr_reloc)
		return libbpf_err(-EINVAL);
	
	return prog->reloc_desc[index].insn_idx;	
}

LIBBPF_API int bpf_reloc__map_idx(struct bpf_program *prog, int index)
{
	if (!prog || index < 0 || index >= prog->nr_reloc)
		return libbpf_err(-EINVAL);
	
	return prog->reloc_desc[index].map_idx;	
}

LIBBPF_API int bpf_reloc__sym_off(struct bpf_program *prog, int index)
{
	if (!prog || index < 0 || index >= prog->nr_reloc)
		return libbpf_err(-EINVAL);
	
	return prog->reloc_desc[index].sym_off;	
}

#endif