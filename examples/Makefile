all: hello library hello_asm hello_bss nasm_ext_c nasm_ext


hello:
	nasm -o hello.o -f elf64 hello.asm
	ld -o hello hello.o

library:
	gcc -o libexample.so -shared library.c
	gcc -o library_client library_client.c -L${PWD} -lexample

hello_asm:
	gcc -o hello_asm hello_asm.c -nostdlib


hello_bss:
	nasm -o hello_bss.o -f elf64 hello_bss.asm
	ld -o hello_bss hello_bss.o

nasm_ext_c:
	nasm -o nasm_ext_c.o -f elf64 nasm_ext.asm
	ld -o nasm_ext_c nasm_ext_c.o -L${PWD} -lexample --dynamic-linker /usr/lib64/ld-linux-x86-64.so.2

nasm_ext:
	nasm -o nasm_ext.o -f elf64 nasm_ext.asm
	nasm -o libnasm.o -f elf64 libnasm.asm
	ld -shared -o libnasm.so libnasm.o
	rm libnasm.o
	ld -o nasm_ext nasm_ext.o -L${PWD} -lnasm --dynamic-linker /usr/lib64/ld-linux-x86-64.so.2

clean:
	rm -f *.o
	rm -f *.so
	rm -f hello
	rm -f library_client
	rm -f hello_asm
	rm -f hello_bss
	rm -f nasm_ext_c
	rm -f nasm_ext
