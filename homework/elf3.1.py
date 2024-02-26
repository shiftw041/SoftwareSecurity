from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/elf-crackme-level3.1"
elf = ELF(challenge_path)
p = process(elf.path)

''' 
objdump -R elf-crackme-level3.1查看动态链接表
-s查看节头表
objdump -d --section=.plt elf-crackme-level3.1查看plt具体代码
发现plt的第一项跳转错误，应该跳到got2
改0x348为08
换到/usr/bin下执行
'''
p.sendafter("Please give me your assembly in bytes (up to 0x1000 bytes): \n",shellcode)
# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)