section .text
    global _start
    extern puts
    extern exit

_start:
    lea rdi, [rel msg]
    call puts

    mov rdi, 0
    call exit

section .rodata
    msg: db 'Hello Puts!', 10, 0