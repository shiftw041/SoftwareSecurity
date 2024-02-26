from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/setuid-backdoor-level3.0"
elf = ELF(challenge_path)
p = process(elf.path)


# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)

# 注意要先转到flag的目录（根目录），运行elf文件后就可以直接使用命令行语句读取flag
# chmod函数用来修改文件权限，可设置参数mode，S_ISUID 04000 设置文件的 (set user-id on execution)位
# 查看根目录文件发现属主属组都是root，hacker目录则是hacker
# 用chmod a+r flag修改权限为所有人可读，a即all
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")

