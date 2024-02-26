from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/pwntools-tutorials-level2.3"
p = process(challenge_path)

# create string
# cld指定方向，rep movsb将rsi开始的一个字节复制到rdi，然后rsi和rdi自增，rcx自减，不断循环直到rcx=0
shellcode = asm('mov rsi, 0x404000; mov rdi, 0x405000; mov rcx, 0x8; cld; rep movsb', arch='amd64', os="windows", log_level="debug")
p.sendafter("Please give me your assembly in bytes (up to 0x1000 bytes): \n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")