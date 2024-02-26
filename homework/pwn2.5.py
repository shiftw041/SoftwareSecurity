from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/pwntools-tutorials-level2.5"
p = process(challenge_path)

# create string
# 用if判断是否为负数，再进行操作
shellcode = asm('pop rax; test rax, rax;js negative; positive: push rax; jmp end; negative:neg rax; push rax; end: ;', arch='amd64', os="windows", log_level="debug")
p.sendafter("Please give me your assembly in bytes (up to 0x1000 bytes): \n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")