#!/bin/bash

get_latest_release() {
    git ls-remote --tags "https://github.com/libbpf/libbpf" | cut -d/ -f3 | tail -n1
}

if [ ! -d "libbpf" ]; then
    git clone "https://github.com/libbpf/libbpf.git"
else
    cd libbpf
    git reset --hard
    git clean -fdx
    cd ..
fi

if [ $# -eq 1 ]; then
    version=$1
else
    version=$(get_latest_release)
fi

cd libbpf
git checkout $version
cd src
echo -e "\n#include \"libbpf_extractor.h\"" >> libbpf.c
INSERT_LINE=$(($(wc -l < libbpf.map) - 1))
sed "s/^/\t\t/; s/$/;/" ../../map_addition.txt > .tmp_1
sed "${INSERT_LINE}r .tmp_1" libbpf.map > .tmp_2
mv .tmp_2 libbpf.map
rm .tmp_1
cd ../..
echo "Successfully installed libbpf $version"