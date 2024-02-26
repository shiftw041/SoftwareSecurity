from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/elf-crackme-level1.2"
elf = ELF(challenge_path)
p = process(elf.path)

# 用readelf -e查看所有头，发现got的offset和addr不一样
# 注意到节头表 Start of section headers: 14928 (bytes into file)，还要排除前面的name、type和flags字段（字、字、双字共16字节）
# 并且出问题的节头表是第24个，还需要排除前面后面的其他节头定位到这个节头，一个节头信息总长为64字节
# 那么这个节头开始于0x3A50+0x40*0x18=0x4050, 应该修改0x4060到0x0x4070，其中0x4060改为b0，0x4061改为3f，0x4068改为b0，0x4069改为2f，其余改为00
# [24] .got  PROGBITS  ffffffffffffffff  ffffffffffffffff改为 0000000000003fb0  00002fb0
# 这关改了之后用utility的功能2获取flag
# okfine突然发现utility里面写了应该改哪里和改成什么，我还自己算了真的是

# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)
