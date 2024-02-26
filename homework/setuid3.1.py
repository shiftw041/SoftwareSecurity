from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/setuid-backdoor-level3.1"
elf = ELF(challenge_path)
p = process(elf.path)


# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)

# 注意要先转到flag的目录（根目录），运行elf文件后就可以直接使用命令行语句读取flag
# chown hacker flag修改文件所有者
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")

