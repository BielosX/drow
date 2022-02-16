.globl _start

.section .text

_start:
    movq $1, %rax
    movq $1, %rdi
    lea msg(%rip), %rsi # it's not (msg + $rip), it's msg relative to %rip, quite confusing.
    movq $STR_LEN, %rdx
    syscall

    movq $60, %rax
    movq $0, %rdi
    syscall

.section .rodata

msg:
    .ascii "Hello World!\n"
msg_len:
    .set STR_LEN, msg_len - msg
