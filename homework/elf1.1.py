from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/elf-crackme-level1.1"
elf = ELF(challenge_path)
p = process(elf.path)

# 对比文件程序头表
# 检查elf文件的 Offset,VirtAddr,PhysAddr 字段，都是8个字节
# 发现第一个程序头表PHDR的三者不一致，需要修改
# offset为可执行目标文件中的偏移量，由此来定位到段的起始位置；VirtAddr为分配的虚拟内存地址；PhysAddr为分配的真实物理地址
# 注意到程序头表的offset开始为64，还要排除前面的type和flags字段（注意64位和32位不同）（word是4个字节）
# PHDR 0xffffffffffffffff 0xffffffffffffffff 0xffffffffffffffff改为0x0000000000000040 0x0000000000000040 0x0000000000000040
# 应该是从64+8字节开始改24个字节，0x48到0x5f：在0x48、0x50、0x58改为40，其他改:00（注意是小端方式存储）
# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)
