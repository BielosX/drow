section .text
    global very_important_function:function

very_important_function:
    push rbp
    mov rbp, rsp

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msg_len
    syscall

    pop rbp
    ret

section .rodata
    msg: db 'Hello from very_important_function!',10
    msg_len: equ $ - msg