section .text
    global _start
    extern puts
    extern _exit
    extern strlen
    extern stdout
    extern fputs_unlocked
    extern fflush_unlocked

_start:
    lea rdi, [rel msg]
    ;call puts
    mov rsi, [rel stdout]
    call fputs_unlocked

    ;mov rdi, [rel stdout]
    ;call fflush_unlocked

    ;lea rdi, [rel msg]
    ;call strlen

    mov rdi, 0
    mov rax, 60
    syscall

    ;mov rdi, 99
    ;call _exit

section .rodata
    msg: db 'Hello Puts!', 10, 0
