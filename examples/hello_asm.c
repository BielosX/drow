#include <stdint.h>
#include <unistd.h>

#define __NR_write 1

int64_t string_length(char* string) {
    int64_t result = 0;
    char* ptr = string;
    while (*ptr != 0) {
        ptr++;
        result++;
    }
    return result;
}

ssize_t my_write(int fd, const void *buf, size_t size)
{
    ssize_t ret;
    asm volatile
    (
        "syscall"
        : "=a" (ret)
        //                 EDI      RSI       RDX
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void my_exit() {
    asm("movq $60, %rax\n\t"
        "movq $0, %rdi\n\t"
        "syscall");
}

void print_hello(void) {
    const char* hello = "Hello World\n";
    int64_t len = string_length(hello);
    my_write(1, hello, len);
}

void _start(void) {
    print_hello();
    my_exit();
}