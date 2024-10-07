#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "ebpf_extractor.h"

static int (*bpf_object__relocate_data_wrapper)(struct bpf_object *, struct bpf_program *) = NULL;
static int (*bpf_map__set_fd)(struct bpf_map *, int) = NULL;
static int (*bpf_program__nr_reloc)(struct bpf_program *) = NULL;
static int (*bpf_reloc__type)(struct bpf_program *, int) = NULL;
static int (*bpf_reloc__insn_idx)(struct bpf_program *, int) = NULL;
static int (*bpf_reloc__map_idx)(struct bpf_program *, int) = NULL;
static int (*bpf_reloc__sym_off)(struct bpf_program *, int) = NULL;


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

    bpf_program__nr_reloc = dlsym(handle, "bpf_program__nr_reloc");

    if (!bpf_program__nr_reloc)
        goto clean;

    bpf_reloc__type = dlsym(handle, "bpf_reloc__type");

    if (!bpf_reloc__type)
        goto clean;

    bpf_reloc__insn_idx = dlsym(handle, "bpf_reloc__insn_idx");

    if (!bpf_reloc__insn_idx)
        goto clean;

    bpf_reloc__map_idx = dlsym(handle, "bpf_reloc__map_idx");

    if (!bpf_reloc__map_idx)
        goto clean;

    bpf_reloc__sym_off = dlsym(handle, "bpf_reloc__sym_off");

    if (!bpf_reloc__sym_off)
        goto clean;

    init = true;
    return EXIT_SUCCESS;

clean:
    fprintf(stderr, "%s\n", dlerror());
    dlclose(handle);
    handle = NULL;
    bpf_object__relocate_data_wrapper = NULL;
    bpf_map__set_fd = NULL;
    dlerror(); // Clear the existing error
    return EXIT_FAILURE;
}

void ebpf_extractor__deinit()
{
    if (!init)
        return;

    dlclose(handle);
    bpf_object__relocate_data_wrapper =  NULL;
    bpf_map__set_fd = NULL;
    bpf_program__nr_reloc = NULL;
    bpf_reloc__type = NULL;
    bpf_reloc__insn_idx = NULL;
    bpf_reloc__map_idx = NULL;
    bpf_reloc__sym_off = NULL;
    init = false;
}

int ebpf_extractor__extract(const char *path)
{
    struct bpf_object *obj = bpf_object__open(path);

    if (!obj)
        return EXIT_FAILURE;

    // Global operation (all programs share the same maps)
    if (ebpf_extractor__extract_maps(obj) != EXIT_SUCCESS) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_program *prog;

    // Local operations (each program has separate instructions and relocations)
    bpf_object__for_each_program(prog, obj) {
        if (bpf_object__relocate_data_wrapper(obj, prog) < 0) {
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }

        if (ebpf_extractor__extract_insns(prog) != EXIT_SUCCESS) {
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }

        if (ebpf_extractor__extract_relocs(prog) != EXIT_SUCCESS) {
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }
    }

    bpf_object__close(obj);
    return EXIT_SUCCESS;
}

int ebpf_extractor__extract_maps(struct bpf_object *obj)
{
    if (!obj || !init)
        return EXIT_FAILURE;

    size_t total_map_string_len = 0;
    size_t total_maps = 0;

    struct bpf_map *map;
    int vfd = 0;

    bpf_object__for_each_map(map, obj) {
        size_t current_map_string_len = snprintf(NULL, 0,
            "%s { type = %d, key_size = %u, value_size = %u, max_entries = %u, fd = %d }",
            bpf_map__name(map),
            bpf_map__type(map),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            vfd  
        );
        total_map_string_len += current_map_string_len;
        ++total_maps;
        ++vfd;
    }

    total_map_string_len += total_maps - 1; // Account for the new line(s)
    ++total_map_string_len; // Account for the null terminator

    char map_string[total_map_string_len];
    size_t current_map = 0;
    size_t offset = 0;
    vfd = 0;

    // Generate the map string
    bpf_object__for_each_map(map, obj) {
        bpf_map__set_fd(map, vfd);
        size_t next_offset = sprintf(map_string + offset,
            "%s { type = %d, key_size = %u, value_size = %u, max_entries = %u, fd = %d }",
            bpf_map__name(map),
            bpf_map__type(map),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            vfd
        );
        offset += next_offset;
        ++vfd;

        // Only add a new line if not the last map
        if (++current_map < total_maps) {
            map_string[offset++] = '\n';
        }
    }

    struct bpf_program *prog;

    // Write the (identical) map string for each program
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        size_t prog_len = strlen(prog_name);
        char output_name[prog_len + strlen(MAP_FILETYPE) + 1];
        ebpf_extractor__fix_progname(prog_name, prog_len, output_name);
        strcat(output_name, MAP_FILETYPE);
        FILE *output_file = fopen(output_name , "w");

        if (!output_file)
            return EXIT_FAILURE;

        fprintf(output_file, "%s", map_string);
        fclose(output_file);
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

int ebpf_extractor__extract_insns(struct bpf_program *prog)
{
    if (!prog)
        return EXIT_FAILURE;

    const char *prog_name = bpf_program__name(prog);
    size_t prog_len = strlen(prog_name);
    char output_name[prog_len + strlen(INSN_FILETYPE) + 1];
    char readable_name[prog_len + strlen(INSN_READABLE_FILETYPE) + 1];
    ebpf_extractor__fix_progname(prog_name, prog_len, output_name);
    ebpf_extractor__fix_progname(prog_name, prog_len, readable_name);
    strcat(output_name, INSN_FILETYPE);
    strcat(readable_name, INSN_READABLE_FILETYPE);
    FILE *output_file = fopen(output_name , "w");
    FILE *readable_file = fopen(readable_name, "w");

    if (!output_file || !readable_file) {
        if (!output_file)
            fclose(readable_file);
        else
            fclose(output_file);
        return EXIT_FAILURE;
    }

    const struct bpf_insn *insns = bpf_program__insns(prog);
    size_t insn_cnt = bpf_program__insn_cnt(prog);

    // Write all of the binary instructions at once
    fwrite(insns, sizeof(struct bpf_insn), insn_cnt, output_file);

    for (size_t i = 0; i < insn_cnt; ++i) {
        struct bpf_insn insn = insns[i];
        fprintf(readable_file, "{%d %d %d %d %d}",
            insn.code,
            insn.src_reg,
            insn.dst_reg,
            insn.off,
            insn.imm
        );

        if (i < insn_cnt - 1) {
            fprintf(readable_file, "\n");
        }
    }

    fclose(output_file);
    fclose(readable_file);
    return EXIT_SUCCESS;
}

int ebpf_extractor__extract_relocs(struct bpf_program *prog)
{
    if (!prog)
        return EXIT_FAILURE;

    int num_relocs = bpf_program__nr_reloc(prog);
    size_t total_reloc_string_len = 0;

    for (int i = 0; i < num_relocs; ++i) {
        int type = bpf_reloc__type(prog, i);
        int insn_idx = bpf_reloc__insn_idx(prog, i);
        int map_idx = bpf_reloc__map_idx(prog, i);
        int sym_off = bpf_reloc__sym_off(prog, i);

        size_t current_reloc_string_len = snprintf(NULL, 0,
            "reloc_%d { type = %d, insn_idx = %d, map_idx = %d, sym_off = %d }",
            i,
            type,
            insn_idx,
            map_idx,
            sym_off
        );
        total_reloc_string_len += current_reloc_string_len;       
    }

    total_reloc_string_len += num_relocs - 1; // Account for the new line(s)
    ++total_reloc_string_len; // Account for the null terminator

    char reloc_string[total_reloc_string_len];
    size_t offset = 0;

    for (int i = 0; i < num_relocs; ++i) {
        int type = bpf_reloc__type(prog, i);
        int insn_idx = bpf_reloc__insn_idx(prog, i);
        int map_idx = bpf_reloc__map_idx(prog, i);
        int sym_off = bpf_reloc__sym_off(prog, i);

        size_t next_offset = sprintf(reloc_string + offset,
            "reloc_%d { type = %d, insn_idx = %d, map_idx = %d, sym_off = %d }",
            i,
            type,
            insn_idx,
            map_idx,
            sym_off
        );
        offset += next_offset;

        if (i < num_relocs - 1) {
            reloc_string[offset++] = '\n';
        }
    }

    const char *prog_name = bpf_program__name(prog);
    size_t prog_len = strlen(prog_name);
    char output_name[prog_len + strlen(RELOC_FILETYPE) + 1];
    ebpf_extractor__fix_progname(prog_name, prog_len, output_name);
    strcat(output_name, RELOC_FILETYPE);
    FILE *output_file = fopen(output_name , "w");

    if (!output_file)
        return EXIT_FAILURE;

    fprintf(output_file, "%s", reloc_string);
    fclose(output_file);
    return EXIT_SUCCESS;
}