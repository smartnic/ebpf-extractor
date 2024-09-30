#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "ebpf_extractor.h"

static int (*bpf_object__relocate_data_wrapper)(struct bpf_object *, struct bpf_program *) = NULL;
static int (*bpf_map__set_fd)(struct bpf_map *, int) = NULL;

static void *handle = NULL;
static bool init = false;

int ebpf_extractor__init()
{
    if (init)
        return EXIT_SUCCESS;

    handle = dlopen("./libbpf/src/libbpf.so", RTLD_NOW | RTLD_LOCAL);

    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return EXIT_FAILURE;
    }

    bpf_object__relocate_data_wrapper = dlsym(handle, "bpf_object__relocate_data_wrapper");

    if (!bpf_object__relocate_data_wrapper)
        goto clean;

    bpf_map__set_fd = dlsym(handle, "bpf_map__set_fd");

    if (!bpf_map__set_fd)
        goto clean;

    init = true;
    return EXIT_SUCCESS;

clean:
    fprintf(stderr, "%s\n", dlerror());
    dlclose(handle);
    handle = NULL;
    bpf_object__relocate_data_wrapper = NULL;
    bpf_map__set_fd = NULL;
    dlerror();
    return EXIT_FAILURE;
}

void ebpf_extractor__deinit()
{
    if (!init)
        return;

    dlclose(handle);
    bpf_object__relocate_data_wrapper =  NULL;
    bpf_map__set_fd = NULL;
    init = false;
}

int ebpf_extractor__extract(const char *path)
{
    struct bpf_object *obj = bpf_object__open(path);

    if (!obj)
        return EXIT_FAILURE;

    if (ebpf_extractor__extract_maps(obj) != EXIT_SUCCESS) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    bpf_object__close(obj);
    return EXIT_SUCCESS;
}

// TODO: remove carriage return
int ebpf_extractor__extract_maps(struct bpf_object *obj)
{
    if (!obj || !init)
        return EXIT_FAILURE;

    size_t total_map_string_len = 0;

    struct bpf_map *map;
    int vfd = 0;

    bpf_object__for_each_map(map, obj) {
        size_t current_map_string_len = snprintf(NULL, 0,
            "%s { type = %d, key_size = %u, value_size = %u, max_entries = %u, fd = %d }\n",
            bpf_map__name(map),
            bpf_map__type(map),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            vfd  
        );
        total_map_string_len += current_map_string_len;
        ++vfd;
    }

    ++total_map_string_len; // Account for the null terminator

    char map_string[total_map_string_len];
    size_t offset = 0;
    vfd = 0;

    bpf_object__for_each_map(map, obj) {
        bpf_map__set_fd(map, vfd);
        size_t next_offset = sprintf(map_string + offset,
            "%s { type = %d, key_size = %u, value_size = %u, max_entries = %u, fd = %d }\n",
            bpf_map__name(map),
            bpf_map__type(map),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            vfd
        );
        offset += next_offset;
        ++vfd;
    }

    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        size_t prog_len = strlen(prog_name);
        char fixed_progname[prog_len + strlen(MAP_FILETYPE) + 1];
        ebpf_extractor__fix_progname(prog_name, prog_len, fixed_progname);
        strcat(fixed_progname, MAP_FILETYPE);
        FILE *output = fopen(fixed_progname , "w");
        fprintf(output, "%s", map_string);
    }

    return EXIT_SUCCESS;
}

void ebpf_extractor__fix_progname(const char *prog_name, const size_t prog_len, char *fixed_progname)
{
    for (size_t i = 0; i < prog_len; ++i) {
        if (prog_name[i] == '/')
            fixed_progname[i] = '-';
        else
            fixed_progname[i] = prog_name[i];
    }

    fixed_progname[prog_len] = '\0';
}