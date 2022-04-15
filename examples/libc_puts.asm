section .text
    global _start
    extern puts
    extern exit
    extern strlen
    extern stdout
    extern fputs_unlocked

_start:
    lea rdi, [rel msg]
    ;call puts
    mov rsi, [rel stdout]
    call fputs_unlocked

    ;lea rdi, [rel msg]
    ;call strlen

    mov rdi, 0
    mov rax, 60
    syscall

    ;mov rdi, 99
    ;call exit

section .rodata
    msg: db 'Hello Puts!', 10, 0