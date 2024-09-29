#ifndef LIBBPF_EXTRACTOR_H
#define LIBBPF_EXTRACTOR_H

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

#endif