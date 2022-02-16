section .text
    global _start

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg] ; lea rsi,[rip + (msg - nextInstruction)]
    mov rdx, msg_len
    syscall
    
    mov rax, 60
    mov rdi, 0
    syscall

section .rodata
    msg: db 'Hello World!',10
    msg_len: equ $ - msg