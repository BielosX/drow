all: hello library hello_asm hello_bss


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

clean:
	rm -f *.o
	rm -f *.so
	rm -f hello
	rm -f library_client
	rm -f hello_asm
	rm -f hello_bss
