section .text
    global _start

_start:

    call hello
    
    mov rax, 60
    mov rdi, 0
    syscall

hello:
    push rbp
    mov rbp, rsp

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg] ; lea rsi,[rip + (msg - nextInstruction)]
    mov rdx, msg_len
    syscall

    mov rsp, rbp
    pop rbp
    ret

section .rodata
    msg: db 'Hello World!',10
    msg_len: equ $ - msg