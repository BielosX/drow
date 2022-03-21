all: hello library hello_asm hello_bss nasm_ext_c nasm_ext

build_path = ${PWD}/build

create_build:
	mkdir -p ${build_path}

hello: create_build
	nasm -o ${build_path}/hello.o -f elf64 hello.asm
	ld -o ${build_path}/hello ${build_path}/hello.o

library: create_build
	gcc -o ${build_path}/libexample.so -shared library.c
	gcc -o ${build_path}/library_client library_client.c -L${build_path} -lexample

hello_asm: create_build
	gcc -o ${build_path}/hello_asm hello_asm.c -nostdlib


hello_bss: create_build
	nasm -o ${build_path}/hello_bss.o -f elf64 hello_bss.asm
	ld -o ${build_path}/hello_bss ${build_path}/hello_bss.o

nasm_ext_c: create_build
	nasm -o ${build_path}/nasm_ext_c.o -f elf64 nasm_ext.asm
	ld -o ${build_path}/nasm_ext_c ${build_path}/nasm_ext_c.o -L${build_path} -lexample --dynamic-linker /usr/lib64/ld-linux-x86-64.so.2

nasm_ext: create_build
	nasm -o ${build_path}/nasm_ext.o -f elf64 nasm_ext.asm
	nasm -o ${build_path}/libnasm.o -f elf64 libnasm.asm
	ld -shared -o ${build_path}/libnasm.so ${build_path}/libnasm.o
	ld -o ${build_path}/nasm_ext ${build_path}/nasm_ext.o -L${build_path} -lnasm --dynamic-linker /usr/lib64/ld-linux-x86-64.so.2

clean:
	rm -f -r ${PWD}/build
