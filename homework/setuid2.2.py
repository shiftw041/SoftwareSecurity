from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/setuid-backdoor-level2.2"
elf = ELF(challenge_path)
p = process(elf.path)


# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)

# 注意要先转到flag的目录（根目录），运行elf文件后就可以直接使用命令行语句读取flag
# chmod函数用来修改文件权限，可设置参数mode，S_ISUID 04000 设置文件的 (set user-id on execution)位
# date指令其实就是用来打印时间的操作，不过flag存储的并不是时间，使用-f参数（打印文件中每一行所展示的时间），这样返回报错的时候会显示不是日期格式的那一行的内容，达到读取flag的目的
# get flag
#flag = p.recvline()
#print(f"flag is: {flag}")

