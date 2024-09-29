CC := gcc
CFLAGS := -Wall -Werror -I./include -I./libbpf/src
LDFLAGS := -L./libbpf/src -l:libbpf.a -lelf -lz
LIBBPF_SRC := ./libbpf/src

.PHONY: all clean

all: ebpf_extractor

$(LIBBPF_SRC)/libbpf.so:
	$(MAKE) -C $(LIBBPF_SRC) CFLAGS="-I../../include" -j$(nproc)

ebpf_extractor.o: ./src/ebpf_extractor.c
	$(CC) $(CFLAGS) -c $< -o $@

main.o: ./src/main.c
	$(CC) $(CFLAGS) -c $< -o $@

ebpf_extractor: $(LIBBPF_SRC)/libbpf.so ebpf_extractor.o main.o
	$(CC) ebpf_extractor.o main.o $(LDFLAGS) -o $@

clean:
	$(MAKE) -C $(LIBBPF_SRC) clean
	rm -f ebpf_extractor.o main.o ebpf_extractor