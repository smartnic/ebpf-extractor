## ebpf-extractor

This repository is a recreation of the [text-extractor](https://github.com/smartnic/bpf-elf-tools/tree/master/text-extractor) tool from [bpf-elf-tools](https://github.com/smartnic/bpf-elf-tools/tree/master).

### Features

This tool aims to parse an eBPF object file and extract various forms of metadata. As input, it takes in an eBPF object file that is internally loaded by libbpf. Then, for *every* program in an object file, ebpf-extractor writes the following files **in the same directory**:

{prog}.insns -- the binary eBPF instructions for the program.

{prog}.maps -- a human-readable representation of the eBPF maps used by the program. In an eBPF object file, all maps are actually shared between all programs. Thus, the .maps file for each program is equal.

{prog}.rel -- a human-readable representation of the relocations applied to the program.

{prog}.txt -- a human-readable representation of the eBPF instructions for the program.

The main purpose of these files is to create input that can be fed into K2, a stochastic eBPF compiler. Namely, K2 requires the .insns and .maps files.

### Motivation

The old text-extractor tool suffers from newer dependencies, such as eBPF object files compiled with newer versions of clang. Oftentimes, it is unable even to open an eBPF object file. This is because it internally utilizes a static version of libbpf -- this is an inevitable constraint as libbpf's source code (libbpf.c) must be altered as both text-extractor and ebpf-extractor access functions and data structures that are **NOT** accessible by the public-facing libbpf API. The goal of this tool, then, is to replicate the same functionalities as text-extractor, while allowing for the usage of ANY libbpf version the user desires.

### Changes

Whereas text-extractor uses a fixed version of libbpf and has its functions directly written to libbpf.c, this tool instead creates various wrapper functions in a header that is simply injected to the end of libbpf.c through an include statement. These wrapper functions are of two types:

1) They call private libbpf functions. non-public libbpf functions are marked *static*, which means they cannot be accessed through any form of dynamic linking. These wrapper functions, then, are non-static versions that call their static counterparts, so that our user-space program *can* dynamically link to these non-static functions.
2) Access data structures whose internal structure is hidden. One example is struct bpf_map. While its pointer type can be stored, it cannot be dereferenced or have its values set, and thus a new function is required.

Essentially, both text-extractor and ebpf-extractor "cheat" libbpf by only borrowing some of its functionality that is usually coupled within a larger process. For example, relocations CANNOT be extracted by themselves; rather, they are applied when an eBPF object is loaded in libbpf. However, we only keep the object file opened in our tool because we do not care about the Linux verifier (which is also part of the loading process).

#### Files

- libbpf_extractor.h: this is the header with the implemented wrapper functions that will be injected into libbpf.c through an include statement.
- ebpf_extractor.h: this is the header for the user-space library ebpf_extractor.c.
- ebpf_extractor.c: this is a user-space library implementation for extracting all the metadata. This library uses dynamic symbol linking (dlopen/dlsym) with the libbpf shared object to obtain function pointers to the wrapper functions.
- main.c: this is the application that calls the ebpf_extractor.
- map_addition: after injecting the non-static wrapper functions into libbpf.c, we also need to "trick" libbpf into thinking these functions are part of the public-facing API. Internally, libbpf keeps track of its public API functions through libbpf.map; functions in map_addition are then injected into this file.

### Usage

First, build the tool by:
1) Installing libbpf with ./libbpf_install.sh {version}. *version* is an optional argument, and omitting it will simply install the newest libbpf release.
2) Compiling the project by running *make*.

This will generate a user-space executable called *ebpf_extractor*. You can run this tool by invoking *./ebpf_extractor <path/to/obj.o>*.

### Notes
- when a function is marked static, it is not in the "symbol lookup table" of an object file, meaning one cannot link to it. Even if they are nonstatic, functions *could* be still marked as private (which is why each function name needed to be added to libbpf.map, which is essentially a list of non-static functions whose symbols should also be public).
- this tool is utilized by [k2-benchmarking](https://github.com/smartnic/k2-benchmarking) to extract the files needed to be fed into K2 (.insns and .maps). However, the .txt input is also used for the benchmarking itself.
