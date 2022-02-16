.globl _start

.section .text

_start:
    movq $1, %rax
    movq $1, %rdi
    # it's not (msg + $rip), it's msg relative to %rip, assembler will count the difference (msg - next_instruction_addr)
    # and then add to %rip value. So if next instruction is at 0x150 and msg is 0x200 this instruction is actually
    # lea 0xB0(%rip), %rsi
    # not
    # lea 0x200(%rip), %rsi
    lea msg(%rip), %rsi
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
