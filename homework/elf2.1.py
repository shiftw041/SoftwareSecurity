from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
#challenge_path = "/challenge/elf-crackme-level2.1"
#elf = ELF(challenge_path)
#p = process(elf.path)

shellcode1 = asm('cmp eax, 0x8', arch='amd64', os="linux", log_level="debug")
print(shellcode1)

shellcode2 = asm('mov esi, 0x2e18', arch='amd64', os="linux")
print(shellcode2)
# 直接看c代码盘逻辑而不是对比修复损失
# 原本是a+b！=8才打印数据，修改ab的值
# objdump -D elf-crackme-level2.1显示所有段
# 看data段修改数据定义 4011字节改为02，改eax
# readelf -e 查看data段开头address在4000 offset是3000
# 所以实际上应该改的是3011字节！！！！
# 用hexdump查看位置正确


# 接收题目的输出
#result = p.recvall()
# 打印题目的输出
#print(result)

