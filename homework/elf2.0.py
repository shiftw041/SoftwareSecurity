from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
#challenge_path = "/challenge/elf-crackme-level2.0"
#elf = ELF(challenge_path)
#p = process(elf.path)

shellcode1 = asm('cmp eax, 0x8', arch='amd64', os="linux", log_level="debug")
print(shellcode1)

shellcode2 = asm('mov esi, 0x2e18', arch='amd64', os="linux")
print(shellcode2)
# 直接看c代码盘逻辑而不是对比修复损失
# 原本是a+b！=8才打印数据，改为！=12
# objdump -d elf-crackme-level2.0查看汇编代码中.text段找main函数
# cmp eax，0x8在第1326行(main+0x31)，为83 f8 08改为0c 也就是改第1328个字节
# readelf -e elf-crackme-level2.0查看text段开头address在1120
# 用hexdump查看位置正确
# utility改了之后检查不正确（不是标答，看utility源码，标答是修改init初始化函数，没看懂），但是能正常打印flag



# 接收题目的输出
#result = p.recvall()
# 打印题目的输出
#print(result)
