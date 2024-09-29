#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#include <libbpf.h>

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

int ebpf_extractor__extract_maps(struct bpf_object *obj) {
    if (!obj || !init)
        return EXIT_FAILURE;

    struct bpf_map *map;
    int vfd = 0;

    bpf_object__for_each_map(map, obj) {
        // TODO: add fix_progname() and write to file.
        bpf_map__set_fd(map, vfd);
        char map_string[128];
        snprintf(map_string, 128,
            "%s { %s = %d, %s = %u, %s = %u, %s = %u, %s = %d }\n", 
            bpf_map__name(map),
            "type", bpf_map__type(map),
            "key_size", bpf_map__key_size(map),
            "value_size", bpf_map__value_size(map),
            "max_entries", bpf_map__max_entries(map),
            "fd", vfd
        );
        vfd++;
        printf("%s\n", map_string);
    }

    // Furthermore, we need to write this for *each* program, cannot forget that. So build up the whole thing above and then write for each prog.
    return EXIT_SUCCESS;
}