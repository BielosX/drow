all: hello library


hello:
	nasm -o hello.o -f elf64 hello.asm
	ld -o hello hello.o

library:
	gcc -o libexample.so -shared library.c
	gcc -o library_client library_client.c -L${PWD} -lexample

clean:
	rm -f *.o
	rm -f *.so
	rm -f hello
	rm -f library_client
