section .text
    global _start
    extern puts
    extern exit
    extern strlen

_start:
    lea rdi, [rel msg]
    call puts

    ;lea rdi, [rel msg]
    ;call strlen

    mov rdi, 0
    mov rax, 60
    syscall

    ;mov rdi, 99
    ;call exit

section .rodata
    msg: db 'Hello Puts!', 10, 0