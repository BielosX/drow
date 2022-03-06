section .text
    global _start


%define BUFFER_SIZE 128

%define READ 0
%define WRITE 1
%define EXIT 60

%define STDIN 0
%define STDOUT 1
%define STDERR 2

%macro write 2
    mov rax, WRITE
    mov rdi, STDOUT
    lea rsi, [rel %1]
    mov rdx, %2
    syscall
%endmacro

%macro read 2
    mov rax, READ
    mov rdi, STDIN
    lea rsi, [rel %1]
    mov rdx, %2
    syscall
%endmacro

%macro exit 1
    mov rax, EXIT
    mov rdi, %1
    syscall
%endmacro

_start:

    write input_msg, input_msg_len

    read buffer, BUFFER_SIZE
    mov r8, rax

    write output_msg, output_msg_len

    write buffer, r8

    exit 13


section .rodata
    input_msg: db 'Input string '
    input_msg_len: equ $ - input_msg 
    output_msg: db 'Your string '
    output_msg_len: equ $ - output_msg

section .bss
    buffer: resb BUFFER_SIZE