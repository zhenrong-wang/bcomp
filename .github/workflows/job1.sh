set -x
set -e
this_dir="$(dirname -- $0)"
cd ${this_dir}
cd ../..
clang -Dfuzz=1 -O0 -g -fsanitize=fuzzer,address -o bcomp.elf bcomp.c
./bcomp.elf -runs=1000000
clang -Dfuzz=1 -O0 -g -fsanitize=fuzzer,signed-integer-overflow -o bcomp.elf bcomp.c
./bcomp.elf -runs=1000000
clang -Dfuzz=1 -O0 -g -fsanitize=fuzzer,memory -o bcomp.elf bcomp.c
./bcomp.elf -runs=1000000
