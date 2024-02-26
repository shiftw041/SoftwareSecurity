from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/setuid-backdoor-level4.2"
elf = ELF(challenge_path)
p = process(elf.path)

# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)

# 注意要先转到flag的目录（根目录），运行elf文件后就可以直接使用命令行语句读取flag
# 编写一个rb程序读取flag  执行ruby /home/hacker/setuid4.2.rb
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")

