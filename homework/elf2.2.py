from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
#challenge_path = "/challenge/elf-crackme-level2.2"
#elf = ELF(challenge_path)
#p = process(elf.path)


# 查看utility，需要把修改的.text字节改回去，直接hash穷举爆破
# .text开始于0x1060 大小0x195 到0x11e4
# 搜索0x9090(注意这两个字节显示的时候不一定放在一起，应该搜90在哪，看附近有没有别的90)
# 找到在0x1169和0x116a
# 目标结果
target_result = "ba4f77d33e8961855bda04916d50f802"

import hashlib

# 读取文件
with open('/challenge/elf-crackme-level2.2', "rb") as file:
        position = 0x1060
        length = 405
        file.seek(position)
        data_read = bytearray(file.read(length))#注意bytes无法修改，需要改成bytesarray

# 穷举第 0x1169 和 0x116A 字节的可能值
for i in range(256):
    for j in range(256):
        data_read[0x1169-0x1060] = i
        data_read[0x116A-0x1060] = j
        print("try:",hex(i), hex(j))
        md5_hash = hashlib.md5(data_read).hexdigest().lower()

        if md5_hash == "ba4f77d33e8961855bda04916d50f802":
            print(f"Found :",hex(i), hex(j))
            exit(0)

print("Matching bytes not found.")
# 最后结果为 0x88 0x99

