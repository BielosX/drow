
section .text
    global _start
    extern very_important_function

_start:
    call very_important_function
    
    mov rax, 60
    mov rdi, 0
    syscall