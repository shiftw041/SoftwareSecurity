from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/pwntools-tutorials-level2.6"
p = process(challenge_path)

# create string
# loop循环累加
shellcode = asm('xor rax,rax;again: add rax,rcx; loop again;', arch='amd64', os="windows", log_level="debug")
p.sendafter("Please give me your assembly in bytes (up to 0x1000 bytes): \n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")