from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/setuid-backdoor-level1.1"
elf = ELF(challenge_path)
p = process(elf.path)


# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")
