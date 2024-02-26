from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/elf-crackme-level1.0"
elf = ELF(challenge_path)
p = process(elf.path)

# 先gcc编译c代码到hacker目录，然后使用文本对比工具
# x86和x64的区别主要在于magicnumber还有机器类型
# 正确的x64机器码和错误的x86机器码
# 0000000 457f 464c 0102 0001 0000 0000 0000 0000
# 0000010 0003 003e 0001 0000 1120 0000 0000 0000

# 0000000 457f 464c 0101 0001 0000 0000 0000 0000
# 0000010 0003 0003 0001 0000 1120 0000 0000 0000
# 也就是说需要用utility修改第0x04字节和0x12字节（特别注意大端小端存储方式！！！）

# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)
